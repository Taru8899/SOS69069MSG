"""Etherscan client tests (fake HTTP, no network)."""
import io, json, os, sys, tempfile, unittest
from unittest import mock
from urllib.parse import parse_qs, urlparse
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg import etherscan
from sos69069_msg.abi import SIGNATURE_RECORDED_TOPIC
from sos69069_msg.config import CONTRACT_ADDRESS
from sos69069_msg.etherscan import EtherscanClient
from sos69069_msg.ethcrypto import normalize_address, parse_address
from sos69069_msg.reader import Inbox, _is_range_error, scan, sync
from sos69069_msg.rpc import RpcError

KEY = "SECRETKEY123"
D = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
SIGNER = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"


class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def topic(a): return "0x" + parse_address(a).rjust(32, b"\0").hex()


def event_data(ph, sig, ts, meta):
    w = lambda n: n.to_bytes(32, "big"); pad = lambda b: b + b"\0" * (-len(b) % 32)
    m = meta.encode()
    return "0x" + (ph + w(128) + w(ts) + w(128 + 32 + len(pad(sig))) + w(len(sig)) + pad(sig)
                   + w(len(m)) + pad(m)).hex()


def row(block, idx, text, ph=b"\x11" * 32, ts=1700000000):
    return {"address": normalize_address(CONTRACT_ADDRESS).lower(),
            "topics": ["0x" + SIGNATURE_RECORDED_TOPIC.hex(), topic(SIGNER), topic(D), topic("0x" + "ab" * 20)],
            "data": event_data(ph, b"\x22" * 65, ts, text),
            "blockNumber": hex(block), "timeStamp": hex(ts), "gasPrice": "0x1", "gasUsed": "0x1",
            "logIndex": "0x" if idx == 0 else hex(idx),          # Etherscan sends "0x" for zero
            "transactionHash": "0x" + f"{block:064x}", "transactionIndex": "0x"}


class FakeServer:
    """Replaces urllib.request.urlopen; `handler(params)` returns the JSON body."""
    def __init__(self, handler): self.handler, self.calls = handler, []
    def __call__(self, req, timeout=None):
        params = {k: v[0] for k, v in parse_qs(urlparse(req.full_url).query).items()}
        self.calls.append(params)
        return Resp(json.dumps(self.handler(params)).encode())


def ok(rows): return {"status": "1", "message": "OK", "result": rows}


class TestClient(unittest.TestCase):
    def patch(self, handler):
        srv = FakeServer(handler)
        p = mock.patch.object(etherscan.urllib.request, "urlopen", srv); p.start(); self.addCleanup(p.stop)
        s = mock.patch.object(etherscan.time, "sleep", lambda *_: None); s.start(); self.addCleanup(s.stop)
        return srv

    def flt(self, lo=100, hi=200):
        return {"address": normalize_address(CONTRACT_ADDRESS), "fromBlock": hex(lo), "toBlock": hex(hi),
                "topics": ["0x" + SIGNATURE_RECORDED_TOPIC.hex(), None, topic(D)]}

    def test_request_shape(self):
        srv = self.patch(lambda p: ok([]))
        EtherscanClient(KEY).get_logs(self.flt())
        p = srv.calls[0]
        self.assertEqual((p["chainid"], p["module"], p["action"], p["apikey"]), ("1", "logs", "getLogs", KEY))
        self.assertEqual((p["fromBlock"], p["toBlock"]), ("100", "200"))     # decimal, as Etherscan wants
        self.assertEqual(p["topic0"], "0x" + SIGNATURE_RECORDED_TOPIC.hex())
        self.assertEqual(p["topic2"], topic(D))
        self.assertEqual(p["topic0_2_opr"], "and")
        self.assertNotIn("topic1", p)
        self.assertEqual((p["page"], p["offset"]), ("1", "1000"))

    def test_zero_hex_is_normalised(self):
        self.patch(lambda p: ok([row(150, 0, "hi")]))
        log = EtherscanClient(KEY).get_logs(self.flt())[0]
        self.assertEqual(log["logIndex"], "0x0")
        self.assertEqual(int(log["logIndex"], 16), 0)                        # would raise on "0x"
        self.assertEqual(int(log["blockNumber"], 16), 150)

    def test_no_records_is_empty_not_error(self):
        self.patch(lambda p: {"status": "0", "message": "No records found", "result": []})
        self.assertEqual(EtherscanClient(KEY).get_logs(self.flt()), [])

    def test_paging(self):
        def h(p):
            page = int(p["page"])
            return ok([row(150 + i, i + 1, "m") for i in range(1000)] if page == 1 else [row(9000, 5, "last")])
        srv = self.patch(h)
        self.assertEqual(len(EtherscanClient(KEY).get_logs(self.flt())), 1001)
        self.assertEqual([c["page"] for c in srv.calls], ["1", "2"])

    def test_result_window_overflow_asks_for_smaller_range(self):
        self.patch(lambda p: ok([row(150, i + 1, "m") for i in range(1000)]))    # every page full
        with self.assertRaises(RpcError) as cm:
            EtherscanClient(KEY).get_logs(self.flt())
        self.assertTrue(_is_range_error(cm.exception))                       # reader will halve the range

    def test_errors_and_key_scrubbing(self):
        self.patch(lambda p: {"status": "0", "message": "NOTOK", "result": "Invalid API Key"})
        with self.assertRaises(RpcError) as cm:
            EtherscanClient(KEY).get_logs(self.flt())
        self.assertIn("Invalid API Key", str(cm.exception))
        self.assertFalse(_is_range_error(cm.exception))                      # must not shrink windows
        def boom(req, timeout=None): raise OSError(f"failed for {req.full_url}")
        with mock.patch.object(etherscan.urllib.request, "urlopen", boom):
            with self.assertRaises(RpcError) as cm:
                EtherscanClient(KEY).block_number()
        self.assertNotIn(KEY, str(cm.exception))                             # key never shown on screen
        with self.assertRaises(RpcError): EtherscanClient("  ")

    def test_rate_limit_retries(self):
        n = {"i": 0}
        def h(p):
            n["i"] += 1
            return {"status": "0", "message": "NOTOK", "result": "Max rate limit reached"} if n["i"] < 3 else ok([])
        self.patch(h)
        self.assertEqual(EtherscanClient(KEY).get_logs(self.flt()), [])
        self.assertEqual(n["i"], 3)
        n["i"] = -99                                                         # always limited -> clear error
        with self.assertRaises(RpcError) as cm: EtherscanClient(KEY).get_logs(self.flt())
        self.assertFalse(_is_range_error(cm.exception))

    def test_block_number(self):
        self.patch(lambda p: {"jsonrpc": "2.0", "id": 83, "result": "0x1312d00"} if p["module"] == "proxy" else {})
        self.assertEqual(EtherscanClient(KEY).block_number(), 20_000_000)
        self.patch(lambda p: {"status": "1", "message": "OK", "result": "21000000"}
                   if p["module"] == "block" else {"jsonrpc": "2.0", "error": {"code": -1}})
        self.assertEqual(EtherscanClient(KEY).block_number(), 21_000_000)    # fallback path


class TestWithReader(unittest.TestCase):
    """Etherscan-format logs flow through the real reader (scan / sync / Inbox)."""
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def server(self, rows, latest=1000):
        def h(p):
            if p["module"] == "proxy": return {"jsonrpc": "2.0", "id": 1, "result": hex(latest)}
            lo, hi = int(p["fromBlock"]), int(p["toBlock"])
            hit = [r for r in rows if lo <= int(r["blockNumber"], 16) <= hi]
            return ok(hit) if hit else {"status": "0", "message": "No records found", "result": []}
        srv = FakeServer(h)
        p = mock.patch.object(etherscan.urllib.request, "urlopen", srv); p.start(); self.addCleanup(p.stop)
        return srv

    def test_sync_shows_messages_including_log_index_zero(self):
        self.server([row(990, 0, "hello from etherscan"), row(995, 3, "second", ph=b"\x33" * 32)])
        inbox = Inbox(os.path.join(self.tmp, "i.json"))
        new = sync(EtherscanClient(KEY), D, inbox)
        self.assertEqual(new, 2)                                             # index-0 log is NOT skipped
        out = inbox.render(D)
        self.assertIn("hello from etherscan", out)
        self.assertIn("second", out)
        self.assertLess(out.index("second"), out.index("hello from etherscan"))   # newest first
        self.assertEqual(inbox.last_block, 1000)

    def test_sync_empty(self):
        self.server([])
        inbox = Inbox(os.path.join(self.tmp, "e.json"))
        self.assertEqual(sync(EtherscanClient(KEY), D, inbox), 0)

    def test_scan_halves_window_on_etherscan_overflow(self):
        rows = [row(50, 1, "early"), row(9500, 2, "late", ph=b"\x44" * 32)]
        def h(p):
            lo, hi = int(p["fromBlock"]), int(p["toBlock"])
            if hi - lo > 4000:
                return {"status": "0", "message": "NOTOK",
                        "result": "Query Timeout occurred. Please select a smaller result dataset"}
            hit = [r for r in rows if lo <= int(r["blockNumber"], 16) <= hi]
            return ok(hit) if hit else {"status": "0", "message": "No records found", "result": []}
        p = mock.patch.object(etherscan.urllib.request, "urlopen", FakeServer(h)); p.start(); self.addCleanup(p.stop)
        msgs = scan(EtherscanClient(KEY), D, 0, 10000)
        self.assertEqual(sorted(m.text for m in msgs), ["early", "late"])


if __name__ == "__main__":
    unittest.main()
