"""RLP / tx / ABI / relayer / reader tests. Network is faked.
Updated for plain-metadata, random-D API (no shared secret, no encryption).
"""
import json, os, secrets, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg import rlp
from sos69069_msg.abi import (RECORD_SIGNATURE_SELECTOR, SIGNATURE_RECORDED_TOPIC,
                              decode_signature_recorded, encode_record_signature)
from sos69069_msg.address_factory import AddressFactory, generate_seed
from sos69069_msg.config import CONTRACT_ADDRESS, MAX_METADATA_LENGTH
from sos69069_msg.conversation import ConversationManager
from sos69069_msg.eip712 import verify_record
from sos69069_msg.ethcrypto import (KeyPair, keccak256, normalize_address, parse_address,
                                    recover_address)
from sos69069_msg.message_engine import prepare_and_sign, short_code
from sos69069_msg.reader import Inbox, scan, sync
from sos69069_msg.relayer import parse_record, submit
from sos69069_msg.rpc import RpcError, _check_url
from sos69069_msg.submission import build_record_signature_call


class TestRlp(unittest.TestCase):
    def test_spec_vectors(self):
        self.assertEqual(rlp.encode(b"dog").hex(), "83646f67")
        self.assertEqual(rlp.encode([b"cat", b"dog"]).hex(), "c88363617483646f67")
        self.assertEqual(rlp.encode(b"").hex(), "80")
        self.assertEqual(rlp.encode([]).hex(), "c0")
        self.assertEqual(rlp.encode(0).hex(), "80")
        self.assertEqual(rlp.encode(15).hex(), "0f")
        self.assertEqual(rlp.encode(1024).hex(), "820400")
        long = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit"
        self.assertEqual(rlp.encode(long).hex(), "b838" + long.hex())

    def test_roundtrip(self):
        x = [b"a" * 60, [b"", b"\x01"], b"\x80"]
        self.assertEqual(rlp.decode(rlp.encode(x)), x)


class TestEIP155Vector(unittest.TestCase):
    def test_signing_hash_and_sender(self):
        to = bytes.fromhex("35" * 20)
        unsigned = [9, 20 * 10**9, 21000, to, 10**18, b"", 1, 0, 0]
        digest = keccak256(rlp.encode(unsigned))
        self.assertEqual(digest.hex(), "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")
        r = 18515461264373351373200002665853028612451056578545711640558177340181847433846
        s = 46948507304638947509940763649030358759909902576025900602547168820602576006531
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27])
        self.assertEqual(recover_address(digest, sig), "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F")


class TestAbi(unittest.TestCase):
    def test_calldata_layout(self):
        data = encode_record_signature(
            "0x" + "11" * 20, "0x" + "22" * 20, b"\x33" * 32, b"\x44" * 65, "hi")
        self.assertEqual(data[:4], RECORD_SIGNATURE_SELECTOR)

    def test_decode_rejects_garbage(self):
        with self.assertRaises(ValueError):
            decode_signature_recorded(b"\x00" * 10)

    def test_event_data_decode(self):
        ph = b"\xaa" * 32
        sig = b"\xbb" * 65
        meta = "hello"
        # Build the same layout decode_signature_recorded expects
        from sos69069_msg.abi import _w, _pad, _dyn
        data = ph + _w(128) + _w(12345) + _w(128 + 32 + len(_pad(sig))) + _dyn(sig)[32:]  # wrong
        # Proper construction matching abi._dyn usage in decode
        sig_enc = _dyn(sig)
        meta_enc = _dyn(meta.encode())
        off_sig = 128
        off_meta = off_sig + len(sig_enc)
        data = ph + _w(off_sig) + _w(12345) + _w(off_meta) + sig_enc + meta_enc
        got_ph, got_sig, ts, got_meta = decode_signature_recorded(data)
        self.assertEqual(got_ph, ph)
        self.assertEqual(got_sig, sig)
        self.assertEqual(ts, 12345)
        self.assertEqual(got_meta, meta)


class FakeRpc:
    def __init__(self, **kw):
        self.chain = kw.get("chain", 1)
        self.base = kw.get("base", 10 * 10**9)
        self.prio = 10**9
        self.gas = 100_000
        self.bal = kw.get("bal", 10**18)
        self.n = 7
        self.sent = []
        self.logs = []
        self.head = 1000
        self.log_calls = []

    def chain_id(self): return self.chain
    def base_fee(self): return self.base
    def priority_fee(self): return self.prio
    def estimate_gas(self, f, t, d): return self.gas
    def balance(self, a): return self.bal
    def nonce(self, a): return self.n
    def send_raw(self, raw):
        self.sent.append(raw)
        return "0x" + keccak256(raw).hex()
    def block_number(self): return self.head
    def get_logs(self, flt):
        self.log_calls.append(flt)
        lo, hi = int(flt["fromBlock"], 16), int(flt["toBlock"], 16)
        return [l for l in self.logs if lo <= int(l["blockNumber"], 16) <= hi]


class TestRelayer(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.tmp = tmp
        self.mgr = ConversationManager(AddressFactory(generate_seed(), os.path.join(tmp, "a.json")))
        self.conv = self.mgr.start_conversation()          # random D, no secret
        key = self.mgr.next_signer(self.conv)
        self.ph, self.meta, self.sig = prepare_and_sign(key, self.conv.rendezvous_d, "hi there")
        call = build_record_signature_call(key.address, self.conv.rendezvous_d, self.ph, self.sig, self.meta)
        self.key = key
        self.json = json.dumps({
            "to": call["to"], "chainId": 1, "signer": key.address,
            "intendedTo": self.conv.rendezvous_d,
            "payloadHash": "0x" + self.ph.hex(),
            "signature": "0x" + self.sig.hex(),
            "metadata": self.meta,
        })
        self.relayer = self.mgr.factory.relayer_key()

    def test_submit_builds_valid_signed_tx(self):
        rpc = FakeRpc()
        txh = submit(rpc, self.relayer, parse_record(self.json))
        raw = rpc.sent[0]
        self.assertEqual(raw[0], 2)
        f = rlp.decode(raw[1:])
        self.assertEqual(int.from_bytes(f[0], "big"), 1)
        self.assertEqual(int.from_bytes(f[1], "big"), 7)
        self.assertEqual(int.from_bytes(f[4], "big"), 120_000)
        self.assertEqual(f[5], parse_address(CONTRACT_ADDRESS))
        self.assertEqual(f[6], b"")
        self.assertEqual(f[7][:4], RECORD_SIGNATURE_SELECTOR)
        digest = keccak256(b"\x02" + rlp.encode(f[:9]))
        sig = f[10].rjust(32, b"\0") + f[11].rjust(32, b"\0") + bytes([27 + int.from_bytes(f[9], "big")])
        self.assertEqual(recover_address(digest, sig), self.relayer.address)
        self.assertEqual(txh, "0x" + keccak256(raw).hex())

    def test_guards(self):
        rec = parse_record(self.json)
        with self.assertRaises(RpcError):
            submit(FakeRpc(chain=5), self.relayer, rec)
        with self.assertRaises(RpcError):
            submit(FakeRpc(base=100 * 10**9), self.relayer, rec)
        with self.assertRaises(RpcError):
            submit(FakeRpc(bal=1000), self.relayer, rec)

    def test_parse_rejects_bad_records(self):
        j = json.loads(self.json)
        for mutate in ({"metadata": "tampered"}, {"to": "0x" + "11" * 20}):
            bad = dict(j, **mutate)
            with self.assertRaises(Exception):
                parse_record(json.dumps(bad))

    def test_relayer_key_distinct_from_signers(self):
        self.assertNotIn(self.relayer.address, self.conv.my_signers)
        again = AddressFactory(self.mgr.factory.master_seed, os.path.join(self.tmp, "x.json"))
        self.assertEqual(again.relayer_key().address, self.relayer.address)

    def test_my_signer_addresses(self):
        f = self.mgr.factory
        self.assertEqual(f.my_signer_addresses(), set(self.conv.my_signers))

    def test_rpc_url_must_be_https(self):
        with self.assertRaises(RpcError):
            _check_url("http://example.com")
        _check_url("https://example.com")
        _check_url("http://127.0.0.1:8545")

    # ---------------- reader helpers ----------------
    def _log(self, block, idx, signer, d, ph, sig, ts, meta, submitter="0x" + "ab" * 20):
        from sos69069_msg.abi import _w, _pad, _dyn
        if isinstance(ph, str):
            ph = bytes.fromhex(ph.removeprefix("0x"))
        sig_enc = _dyn(sig)
        meta_enc = _dyn(meta.encode())
        off_sig = 128
        off_meta = off_sig + len(sig_enc)
        data = ph + _w(off_sig) + _w(ts) + _w(off_meta) + sig_enc + meta_enc
        t = lambda a: "0x" + parse_address(a).rjust(32, b"\0").hex()
        return {
            "blockNumber": hex(block),
            "logIndex": hex(idx),
            "transactionHash": "0x" + f"{block:064x}",
            "data": "0x" + data.hex(),
            "topics": [
                "0x" + SIGNATURE_RECORDED_TOPIC.hex(),
                t(signer), t(d), t(submitter),
            ],
        }

    def test_sync_shows_everything_sent_to_d(self):
        rpc = FakeRpc()
        d = self.conv.rendezvous_d
        rpc.logs = [
            self._log(990, 0, self.key.address, d, self.ph, self.sig, 1700000000, self.meta),
            self._log(991, 0, self.key.address, d, b"\x01" * 32, self.sig, 1700000001, "plain hello"),
        ]
        inbox = Inbox(os.path.join(self.tmp, "inbox.json"))
        new = sync(rpc, d, inbox)
        self.assertEqual(new, 2)
        out = inbox.render(d)
        self.assertIn("hi there", out)
        self.assertIn("plain hello", out)
        self.assertIn("#", out)                    # short codes present
        self.assertEqual(inbox.last_block, 1000)

    def test_lagging_rpc_overlap(self):
        rpc = FakeRpc()
        d = self.conv.rendezvous_d
        rpc.logs = [self._log(990, 0, self.key.address, d, self.ph, self.sig, 1700000000, self.meta)]
        inbox = Inbox(os.path.join(self.tmp, "lag.json"))
        sync(rpc, d, inbox)
        rpc.head = 1010
        rpc.log_calls.clear()
        new = sync(rpc, d, inbox)
        self.assertEqual(new, 0)
        # overlap re-scan
        self.assertEqual(int(rpc.log_calls[0]["fromBlock"], 16), 1001 - 20)

    def test_range_limited_rpc(self):
        rpc = FakeRpc()
        d = self.conv.rendezvous_d
        rpc.logs = [
            self._log(100, 0, self.key.address, d, self.ph, self.sig, 1700000000, self.meta),
            self._log(9500, 0, self.key.address, d, b"\x02" * 32, self.sig, 1700000001, "late"),
        ]
        orig = rpc.get_logs

        def limited(flt):
            if int(flt["toBlock"], 16) - int(flt["fromBlock"], 16) > 3000:
                raise RpcError("eth_getLogs: query exceeds max block range 2000")
            return orig(flt)

        rpc.get_logs = limited
        msgs = scan(rpc, d, 0, 10000)
        self.assertEqual(len(msgs), 2)

        def broken(flt):
            raise RpcError("eth_getLogs: HTTP Error 403: Forbidden")

        rpc.get_logs = broken
        with self.assertRaises(RpcError):
            scan(rpc, d, 0, 10000)

    def test_pending_until_on_chain(self):
        inbox = Inbox(os.path.join(self.tmp, "pend.json"))
        ph_hex = "0x" + self.ph.hex()
        inbox.add_pending(ph_hex, "hi there")
        out = inbox.render(self.conv.rendezvous_d)
        self.assertIn("NOT submitted yet", out)
        self.assertIn("hi there", out)
        # Simulate on-chain arrival
        rpc = FakeRpc()
        d = self.conv.rendezvous_d
        rpc.logs = [self._log(990, 0, self.key.address, d, self.ph, self.sig, 1700000000, self.meta)]
        sync(rpc, d, inbox)
        out2 = inbox.render(d)
        self.assertNotIn("NOT submitted yet", out2)

    def test_inbox_render_newest_first_and_labels_you(self):
        rpc = FakeRpc()
        d = self.conv.rendezvous_d
        k2 = self.mgr.next_signer(self.conv)
        ph2, meta2, sig2 = prepare_and_sign(k2, d, "second one")
        rpc.logs = [
            self._log(990, 0, self.key.address, d, self.ph, self.sig, 1700000000, self.meta),
            self._log(995, 0, k2.address, d, ph2, sig2, 1700000500, meta2),
        ]
        inbox = Inbox(os.path.join(self.tmp, "inbox2.json"))
        sync(rpc, d, inbox)
        out = inbox.render(d, mine={self.key.address})
        self.assertLess(out.index("second one"), out.index("hi there"))
        self.assertIn("you", out)
        self.assertIn("from " + k2.address[:6], out)
        self.assertIn("#", out)

    def test_start_conversation_with_pasted_d(self):
        d = "0x" + "ab" * 20
        conv = self.mgr.start_conversation(d=d)
        self.assertEqual(conv.rendezvous_d.lower(), d.lower())

    def test_short_code(self):
        self.assertEqual(short_code("0xabcdef12" + "00" * 28), "ABCD")

    def test_message_too_long_rejected(self):
        key = self.mgr.next_signer(self.conv)
        with self.assertRaises(ValueError):
            prepare_and_sign(key, self.conv.rendezvous_d, "x" * (MAX_METADATA_LENGTH + 1))


if __name__ == "__main__":
    unittest.main()
