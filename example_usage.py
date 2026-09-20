"""CLI demo of the core (no UI, no network):  python example_usage.py"""
import os, secrets, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from sos69069_msg.address_factory import AddressFactory, generate_seed
from sos69069_msg.conversation import ConversationManager
from sos69069_msg.eip712 import verify_record
from sos69069_msg.message_engine import prepare_and_sign, read_record

tmp = tempfile.mkdtemp()
a = ConversationManager(AddressFactory(generate_seed(), os.path.join(tmp, "a.json")))
b = ConversationManager(AddressFactory(generate_seed(), os.path.join(tmp, "b.json")))

secret = secrets.token_bytes(32)          # exchanged out-of-band
ca, cb = a.start_conversation(secret), b.start_conversation(secret)
assert ca.rendezvous_d == cb.rendezvous_d
D = ca.rendezvous_d
print("Rendezvous D:", D)

key = a.next_signer(ca)
ph, meta, sig = prepare_and_sign(key, D, "Hello from A", secret)
assert verify_record(key.address, D, ph, meta, sig)
print("metadata:", meta, "\nsignature:", "0x" + sig.hex())
print("B reads:", read_record(meta, ph, secret))
