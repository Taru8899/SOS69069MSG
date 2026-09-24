# SOS69069 MSG

Messenger for the SOS 69069 ledger on Ethereum mainnet
(`0x7373DBC24Dcd785896E8Ac3d5372c6ced9B75a8A`).

There's no server, no
account system, and no database — every message is a public, self-signed
record on-chain, and the app on your phone is the only thing that knows
which records belong to your conversation.

This document explains **what the app does, why it's built this way, and
what its limits are** — in plain language, then in detail.

---

## The idea in one paragraph

Normally a "message" implies a sender and a recipient tied together
somewhere. Here, that link never touches the blockchain. Each person only
ever posts messages **to themselves** — a "self-post." Your app privately
remembers your conversation partner's address, and when it reads the
chain it pulls in both your self-posts and theirs, merges them by time,
and shows you a normal-looking chat. Anyone else watching the chain just
sees two addresses independently talking to themselves; the fact that
they're actually talking to *each other* only exists inside your app.

---

## How a conversation works

### 1. Setup — create your identity, add the other person

- Tap **Generate my wallet** to create a brand-new, passwordless wallet.
  The private key is generated randomly and stays on your device.
- Share **your address** with the other person (it's just a public
  address — safe to send over any channel).
- Paste **their address** into the app and tap **Start conversation**.

That's it — no shared secret, no password, no account creation on a
server. The pairing `(My address, Their address)` is saved locally as a
small file on your device, and it's the *only* place that pairing exists.

### 2. Send — write and sign a message

- Type your message (up to 64 characters).
- Optionally prefix it with a short reply code (like `#A3F2`) if you're
  replying to a specific earlier message.
- Tap **Sign**. This uses your device's private key to produce an
  EIP-712 signature. **Signing is free** — nothing is broadcast yet, so
  no gas is spent at this step.

### 3. Relay — pay the gas, broadcast it

Signing a message and paying to publish it are two separate steps on
purpose, so either person can cover the cost:

- **You pay:** send a small amount of ETH to your relayer address (shown
  on the Relay tab), then tap **Submit to Ethereum**.
- **Someone else pays:** copy the signed JSON and send it to anyone —
  they paste it into their own Relay tab and submit it for you.

Before anything is broadcast, the app runs a few safety checks (see
below), so a bad or duplicate signature is caught locally instead of
wasting gas.

### 4. Check — read the conversation

- Tap **Refresh from chain**. The app looks up every self-post from your
  address and every self-post from the other person's address, merges
  them in chronological order, and labels each one **Me** or **Other**.
- The first scan looks back roughly 50,000 blocks (about a week); you
  can enter an earlier block number to search further back.
- Scans are incremental — once you've refreshed once, later refreshes
  only fetch what's new, using a local cache.
- Messages you've signed but not yet submitted show up at the top,
  marked **⏳ Not submitted yet**.

### Ending a conversation

**End conversation** deletes the locally stored pairing and the message
cache. The chain records themselves aren't erased (they can't be — it's
a public blockchain), but the *link* saying those two addresses were
talking to each other only lived in your app, and now it's gone. The
next conversation starts from a clean page.

---

## What's actually happening on-chain

Every message is recorded as a `SignatureRecorded` event with three
relevant fields:

| Field | Meaning |
|---|---|
| `signer` | The wallet that signed the message |
| `intendedTo` | **Always the same as `signer`** — you only ever address yourself |
| `metadata` | The plain-text message, up to 64 bytes |

Because `intendedTo` always equals `signer`, there's no on-chain
concept of "A messaging B." There's no thread ID, no shared address, no
pairing — just two independent streams of self-addressed posts. Your
app is what interprets `A`'s stream and `B`'s stream as one
conversation, purely because *you* told it those two addresses go
together.

```text
On-chain:              A → A          B → B
                     (self-post)   (self-post)

Off-chain (your app):  "A and B are the same conversation"
                        — known only on your device
```

---

## Safety rails when submitting

Before a signed message is broadcast, the app:

- **Verifies the signature locally** before doing anything else.
- **Dry-runs the transaction** via `eth_estimateGas`, which reverts
  automatically on duplicate or invalid signatures — catching problems
  before they cost gas.
- **Refuses to submit** if the connected RPC isn't Ethereum mainnet
  (chain ID 1), if current gas exceeds your configured cap (50 gwei by
  default), or if your relayer wallet doesn't have enough ETH to cover
  it.
- **Never trusts a pasted record's destination.** Even if someone hands
  you a doctored JSON blob, the transaction always targets the real
  SOS 69069 contract — the `to` field in a pasted record is ignored.
- **Requires HTTPS** for any RPC endpoint, except for local testing
  (`http://127.0.0.1`).

---

## Design choices worth knowing

- **No `web3.py` / `eth-account`.** Those libraries pull in dependencies
  (`pydantic-core`, `ckzg`) with no Android wheels, which would block
  building a mobile app. Instead, everything needed — Keccak hashing,
  EIP-712 signing, EIP-1559 transactions, RLP encoding, and ABI
  encoding — is implemented directly on top of the `cryptography`
  library and the Python standard library, and checked against
  published test vectors (the official EIP-712 "Mail" example, the
  EIP-155 worked example, the RLP spec, and Keccak test vectors).
- **Deterministic key derivation.** Your signer keys and relayer key are
  both derived from one seed using HKDF:
  - `signer_i = HKDF(seed, "sos69069/signer/i")`
  - `relayer  = HKDF(seed, "sos69069/relayer/0")`

  This means losing the app doesn't mean losing your keys — as long as
  you've backed up the seed, everything regenerates from it.
- **The seed is stored unencrypted** in the app's private storage on
  your device. Back it up somewhere safe; anyone with the seed can
  recreate all your keys.
- **Message format:** `metadata` is plain text (no encryption layer in
  this version), capped at 64 bytes.

---

## Limits — please read before relying on this

- **This is not anonymous.** The rendezvous pattern, signer addresses,
  message timing, and message content are all public. Two addresses can
  potentially be linked as a conversation by anyone who has the same
  information your app has (or who guesses well).
- **Submitting from your own relayer links your identity to timing.**
  If that matters to you, have someone else submit the transaction
  instead.
- **No forward secrecy and no access control.** Since there's no shared
  secret in this version, anyone who knows both addresses can, in
  principle, read the public messages tied to them. Treat this as a
  public bulletin board, not a private mailbox.
- **Your RPC provider can see you.** Whoever runs the RPC endpoint you
  connect to sees your IP address and which addresses you're querying.
- **The relayer key is a hot wallet** living in app storage — only ever
  fund it with small amounts you're comfortable losing.
- **Batched submission (`recordSignatureOne`) exists in the contract
  but isn't wired into the app yet.**

---

## Building it yourself

```bash
pip install cryptography
python -m unittest discover tests -v     # run the test suite
python example_usage.py                  # see it work end-to-end
pip install briefcase && briefcase dev   # run the desktop UI
```

**Android APK:** push to GitHub and the *Android APK* workflow builds
it automatically (or trigger it manually from the Actions tab).
Download `sos69069-msg-debug-apk` from the run's artifacts, or tag a
release (`v*`) to attach it automatically. The build is debug-signed,
which is fine for sideloading onto your own device but not for
publishing to the Play Store — that needs a release keystore.
