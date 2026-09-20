# sos69069 msg

Messenger for the SOS 69069 ledger on Ethereum mainnet
(`0x7373DBC24Dcd785896E8Ac3d5372c6ced9B75a8A`).

- Shared secret → rendezvous address **D** (everyone with the secret derives the same D)
- One-time signer key per message, derived from your seed
- Message in the 64-byte `metadata` field, encrypted (ChaCha20-Poly1305)
- **Send** signs it · **Relay** broadcasts it · **Inbox** reads and decrypts from chain logs

## Using the app
1. **Setup:** create an identity (back up the seed), generate or paste the shared secret,
   start the conversation. Both people must use the same secret; then both see the same D.
2. **Send:** type a message (≤ 32 bytes encrypted) → *Sign message*. Signing costs nothing.
3. **Relay:** the signed record is prefilled. Anyone can submit it and pay the gas:
   - you: send a little ETH to your relayer address (shown on the tab), press *Submit to Ethereum*;
   - or hand the JSON to another person, who pastes it into their Relay tab.
4. **Inbox:** *Refresh from chain* fetches `SignatureRecorded` logs for D, decrypts what
   belongs to your conversation, ignores the rest. Scans are incremental and cached.
   First scan looks back ~50,000 blocks (~1 week); enter a block number to go further back.

### Safety rails when submitting
- Signature is verified locally first; the contract call is dry-run via `eth_estimateGas`
  (reverts on duplicates or bad signatures) before anything is sent.
- Refuses if the RPC isn't chain 1, if gas exceeds your cap (default 50 gwei),
  or if the relayer is underfunded.
- A pasted record's `to` field is never trusted; the destination is always the contract.
- RPC URLs must be `https://` (plain http only for localhost, e.g. an anvil fork).

## Build the APK
Push to GitHub → the **Android APK** workflow runs (or run it from the *Actions* tab) →
download `sos69069-msg-debug-apk` from the run's artifacts. Tag `v*` to attach it to a Release.
Debug-signed: fine for sideloading; Play Store needs a release keystore.

```bash
pip install cryptography
python -m unittest discover tests -v     # 30 tests
python example_usage.py
pip install briefcase && briefcase dev   # desktop UI
```

## Design notes
- No `web3`/`eth-account`: their deps (`pydantic-core`, `ckzg`) have no Android wheels.
  Everything needed (keccak, EIP-712, EIP-1559 tx signing, RLP, ABI, JSON-RPC) is
  implemented on `cryptography` + stdlib and checked against published vectors
  (EIP-712 Mail example, EIP-155 worked example, RLP spec, keccak).
- Keys: `signer_i = HKDF(seed, "sos69069/signer/i")`, relayer = `HKDF(seed, "sos69069/relayer/0")`.
  The seed is stored unencrypted in the app's private storage: back it up.
- Message format: `metadata = base64url(AEAD(plaintext))`, nonce = `payloadHash[:12]`, AAD = `payloadHash`.

## Limits
- Not anonymous. D, signers, timing and ciphertext are public; a conversation is linkable via D.
  Submitting from your own relayer links that address to the record's timing; have someone
  else submit if that matters. Your RPC provider sees your IP and which D you watch.
- Anyone with the shared secret can read and write; no forward secrecy.
- The relayer key is a hot wallet in app storage: only ever fund it with small amounts.
- `recordSignatureOne` (batching) isn't wired into the app yet.
