"""RLP / tx / ABI / relayer / reader tests. Network is faked.
Updated for plain-metadata, random-D API (no shared secret, no encryption).
"""
import json, os, secrets, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg import rlp
from sos69069_msg.abi import (RECORD_SIGNATURE_SELECTOR, SIGNATURE_RECORDED_TOPIC,
                              decode_signature_recorded, encode_record_signature)
from sos69069_msg.config import CONTRACT_ADDRESS, MAX_METADATA_LENGTH
from sos69069_msg.eip712 import verify_record
from sos69069_msg.ethcrypto import (KeyPair, keccak256, normalize_address, parse_address,
                                    recover_address)
from sos69069_msg.message_engine import prepare_and_sign, short_code
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



class TestRelayerGuardsSmoke(unittest.TestCase):
    """Messaging pair logic is covered by test_pair_flow / test_flow."""
    def test_rpc_url_https(self):
        from sos69069_msg.rpc import RpcError, _check_url
        with self.assertRaises(RpcError):
            _check_url("http://example.com")
        _check_url("https://example.com")
        _check_url("http://127.0.0.1:8545")


if __name__ == "__main__":
    unittest.main()
