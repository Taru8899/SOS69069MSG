"""
End-to-end example:
1. Two users share a secret
2. Both independently derive the SAME rendezvous address D
3. Each signs a short encrypted message into the 64-char metadata field
4. Signatures are verified locally, then the other side decrypts the record
"""

import secrets
import tempfile
import os

from address_factory import AddressFactory
from conversation import ConversationManager
from eip712 import verify_record
from message_engine import prepare_and_sign, read_record
from submission import build_record_signature_call

MNEMONIC_A = "test test test test test test test test test test test junk"
MNEMONIC_B = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def main():
    tmp = tempfile.mkdtemp()
    mgr_a = ConversationManager(AddressFactory(MNEMONIC_A, os.path.join(tmp, "a.json")))
    mgr_b = ConversationManager(AddressFactory(MNEMONIC_B, os.path.join(tmp, "b.json")))

    shared_secret = secrets.token_bytes(32)  # in real life exchanged via Signal / in person

    conv_a = mgr_a.start_conversation(shared_secret)
    conv_b = mgr_b.start_conversation(shared_secret)
    assert conv_a.rendezvous_d == conv_b.rendezvous_d, "A and B must derive the same D"
    D = conv_a.rendezvous_d
    print(f"Rendezvous D = {D}")

    # A -> D
    signer_a, acct_a = mgr_a.next_signer(conv_a)
    ph, meta, sig = prepare_and_sign(acct_a, signer_a, D, "Hello from A", shared_secret)
    assert verify_record(signer_a, D, ph, meta, sig)
    print("\nA's call (hand to any relayer):")
    print(build_record_signature_call(signer_a, D, ph, sig, meta))

    # B reads it from the chain event (metadata + payloadHash) and decrypts
    print("\nB decrypts:", read_record(meta, ph, shared_secret))

    # B -> D
    signer_b, acct_b = mgr_b.next_signer(conv_b)
    ph2, meta2, sig2 = prepare_and_sign(acct_b, signer_b, D, "Hello from B", shared_secret)
    assert verify_record(signer_b, D, ph2, meta2, sig2)
    print("A decrypts:", read_record(meta2, ph2, shared_secret))


if __name__ == "__main__":
    main()
