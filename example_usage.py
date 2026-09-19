"""
Minimal end-to-end example:
1. Two users share a secret
2. Both derive the same D
3. Each signs a short message into the 64-char metadata field
4. The signed records are ready for a random relayer / credit holder to submit
"""

from eth_account import Account
from address_factory import AddressFactory
from conversation import ConversationManager
from message_engine import prepare_and_sign
from submission import build_record_signature_call
import secrets


def main():
    # --- User A ---
    mnemonic_a = "test test test test test test test test test test test junk"
    factory_a = AddressFactory(mnemonic_a, "used_a.json")
    mgr_a = ConversationManager(factory_a)

    # --- User B ---
    mnemonic_b = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    factory_b = AddressFactory(mnemonic_b, "used_b.json")
    mgr_b = ConversationManager(factory_b)

    # Shared secret (in real life comes from Signal / Tor / etc.)
    shared_secret = secrets.token_bytes(32)

    # Both start the conversation → independently obtain the same D
    conv_a = mgr_a.start_conversation(shared_secret, my_index_base=0)
    conv_b = mgr_b.start_conversation(shared_secret, my_index_base=0)

    assert conv_a.rendezvous_d == conv_b.rendezvous_d
    D = conv_a.rendezvous_d
    print(f"Rendezvous D = {D}")

    # User A signs a message
    signer_a = conv_a.my_signers[0]
    acct_a = Account.from_mnemonic(mnemonic_a, account_path="m/44'/60'/2'/0/0")
    payload_hash_a, metadata_a, sig_a = prepare_and_sign(
        acct_a, signer_a, D, "Hello from A", shared_secret
    )
    call_a = build_record_signature_call(signer_a, D, payload_hash_a, sig_a, metadata_a)
    print("\nUser A ready-to-submit call:")
    print(call_a)

    # User B signs a message
    signer_b = conv_b.my_signers[0]
    acct_b = Account.from_mnemonic(mnemonic_b, account_path="m/44'/60'/2'/0/0")
    payload_hash_b, metadata_b, sig_b = prepare_and_sign(
        acct_b, signer_b, D, "Hello from B", shared_secret
    )
    call_b = build_record_signature_call(signer_b, D, payload_hash_b, sig_b, metadata_b)
    print("\nUser B ready-to-submit call:")
    print(call_b)

    print("\nAny unrelated user (or community relayer) can now broadcast these calls.")
    print("The 64-character metadata field carries the actual messages.")


if __name__ == "__main__":
    main()
