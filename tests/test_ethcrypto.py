"""Checks against well-known Ethereum / EIP-712 test vectors."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from sos69069_msg.ethcrypto import (KeyPair, keccak256, recover_address, to_checksum,
                                address_of_private_key, N)
from sos69069_msg.eip712 import eip712_digest


def k(s): return keccak256(s.encode())
def pad_addr(a): return bytes.fromhex(a[2:]).rjust(32, b"\0")


class TestKeccak(unittest.TestCase):
    def test_vectors(self):
        self.assertEqual(keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")

    def test_multi_block(self):  # >136 bytes exercises absorb loop
        self.assertEqual(len(keccak256(b"a" * 500)), 32)
        self.assertNotEqual(keccak256(b"a" * 135), keccak256(b"a" * 136))


class TestAddresses(unittest.TestCase):
    def test_privkey_one(self):
        self.assertEqual(address_of_private_key((1).to_bytes(32, "big")),
                         "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")

    def test_eip55(self):
        a = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        self.assertEqual(to_checksum(bytes.fromhex(a[2:].lower())), a)


class TestEIP712Mail(unittest.TestCase):
    """The canonical example from the EIP-712 spec."""
    cow = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
    bob = "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"

    def digest(self):
        dom_t = k("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
        dom = keccak256(dom_t + k("Ether Mail") + k("1") + (1).to_bytes(32, "big")
                        + pad_addr("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"))
        self.assertEqual(dom.hex(), "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f")
        person_t = k("Person(string name,address wallet)")
        mail_t = k("Mail(Person from,Person to,string contents)Person(string name,address wallet)")
        frm = keccak256(person_t + k("Cow") + pad_addr(self.cow))
        to = keccak256(person_t + k("Bob") + pad_addr(self.bob))
        mail = keccak256(mail_t + frm + to + k("Hello, Bob!"))
        return eip712_digest(dom, mail)

    def test_digest(self):
        self.assertEqual(self.digest().hex(),
                         "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")

    def test_known_signature_recovers_cow(self):
        sig = (0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d.to_bytes(32, "big")
               + 0x07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562.to_bytes(32, "big")
               + bytes([28]))
        self.assertEqual(recover_address(self.digest(), sig), self.cow)

    def test_cow_key(self):
        key = keccak256(b"cow")
        self.assertEqual(address_of_private_key(key), self.cow)


class TestSigning(unittest.TestCase):
    def test_sign_recover_low_s_many(self):
        kp = KeyPair.from_private_key(keccak256(b"cow"))
        for i in range(25):
            d = keccak256(b"msg%d" % i)
            sig = kp.sign_digest(d)
            self.assertEqual(len(sig), 65)
            self.assertLessEqual(int.from_bytes(sig[32:64], "big"), N // 2)
            self.assertIn(sig[64], (27, 28))
            self.assertEqual(recover_address(d, sig), kp.address)


if __name__ == "__main__":
    unittest.main()
