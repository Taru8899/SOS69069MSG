# SOS 69069 Messaging Client

Python client for the SOS 69069 ledger (Ethereum mainnet):
`0x7373DBC24Dcd785896E8Ac3d5372c6ced9B75a8A`

- Shared secret → rendezvous address **D** (both sides derive the same D)
- One-time signer address per message, from your mnemonic
- Message carried in the 64-byte `metadata` field, encrypted (ChaCha20-Poly1305)
- Anyone can submit the signed record and pay the gas

```bash
pip install -r requirements.txt
python example_usage.py                 # CLI demo
python ui.py                            # Gradio UI
python -m unittest discover tests       # crypto tests (no eth libs needed)
```

## Message format
`metadata = base64url(ChaCha20-Poly1305(plaintext))`, nonce = `payloadHash[:12]`,
AAD = `payloadHash`. Max **32 bytes** of plaintext per record (or 64 bytes if you
turn encryption off). Longer messages are rejected, never truncated; split them
across records.

To read: query `SignatureRecorded` logs where `intendedTo == D`, then call
`message_engine.read_record(metadata, payloadHash, secret)`. Records that fail
to decrypt are not from your conversation (anyone can write to any D).

## Limits you should know about
- **Not anonymous.** D, signer addresses, timing and ciphertext are all public.
  All messages in a conversation are linkable through D. Whoever submits a
  record sees its contents before broadcasting (only ciphertext if encrypted).
- Anyone holding the shared secret can read *and* write in the conversation.
  There is no forward secrecy: leaking the secret exposes all past messages.
- `gas_credits.py` is a local, self-reported stub with no security.
- Nothing here broadcasts transactions or reads logs yet.
- Signing was written against the contract's EIP-712 type and chain id 1;
  before real use, run one signed record through a mainnet fork (e.g. Foundry
  `anvil --fork-url ...`) to confirm the contract accepts it.
