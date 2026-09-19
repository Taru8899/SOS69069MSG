# SOS 69069 Privacy Messaging Client

Python implementation of the full architecture:

- One-time, role-separated addresses
- Shared-secret → rendezvous address **D**
- Messages carried inside the **64-character `metadata` field** of SOS 69069
- Signers never pay gas
- Community relayers + reciprocal gas credits
- Contract: `0x7373DBC24Dcd785896E8Ac3d5372c6ced9B75a8A`

## Quick start

```bash
pip install -r requirements.txt
python example_usage.py          # CLI demo
python ui.py                     # Gradio web UI
```

## Files

| File                | Purpose                                      |
|---------------------|----------------------------------------------|
| `config.py`         | Contract address, EIP-712 domain, paths      |
| `crypto_utils.py`   | HKDF, encryption helpers                     |
| `address_factory.py`| Role-separated one-time address derivation   |
| `eip712.py`         | Exact EIP-712 matching the contract          |
| `conversation.py`   | Start A+B→D, later add more signers          |
| `message_engine.py` | Pack message into 64-char metadata + sign    |
| `submission.py`     | Build `recordSignature` / `recordSignatureOne` calls |
| `gas_credits.py`    | Local reciprocal credit stub                 |
| `ui.py`             | Gradio web interface                         |
| `example_usage.py`  | Minimal CLI walk-through                     |

## Building an APK later

You can wrap this logic with:

- BeeWare / Briefcase
- Kivy / Buildozer
- or expose the core modules to a Flutter / React-Native front-end

and publish the APK via GitHub Actions.

## Security notes

- Master mnemonic and shared secrets never leave the device.
- All addresses are one-time and role-separated.
- The on-chain metadata field is the message carrier (≤ 64 chars).
- Gas is paid by community relayers or random unrelated users holding credits.
