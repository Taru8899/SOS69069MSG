"""
Simple Gradio UI for the SOS 69069 privacy messaging client.

Features:
- Generate / paste a mnemonic
- Create a shared secret
- Start a conversation (derive D + one-time signers)
- Compose a short message (fits in 64-char metadata)
- Produce a ready-to-submit signed Record
- View gas-credit balance (local stub)
"""

import gradio as gr
import secrets
import json
from eth_account import Account
from eth_utils import to_hex

from address_factory import AddressFactory
from conversation import ConversationManager
from message_engine import prepare_and_sign, read_record
from eip712 import verify_record
from submission import build_record_signature_call
from gas_credits import GasCreditBook
from config import CONTRACT_ADDRESS, MAX_METADATA_LENGTH, CHAIN_ID
from crypto_utils import MAX_PLAINTEXT_BYTES

# In-memory session state (for demo only)
state = {
    "mnemonic": None,
    "factory": None,
    "mgr": None,
    "conv": None,
    "shared_secret": None,
    "credits": GasCreditBook(),
}


def generate_mnemonic():
    _, mnemonic = Account.create_with_mnemonic()
    state["mnemonic"] = mnemonic
    state["factory"] = AddressFactory(mnemonic, "ui_used.json")
    state["mgr"] = ConversationManager(state["factory"])
    return mnemonic


def set_mnemonic(mnemonic: str):
    if not mnemonic or len(mnemonic.split()) < 12:
        return "Invalid mnemonic"
    state["mnemonic"] = mnemonic.strip()
    state["factory"] = AddressFactory(state["mnemonic"], "ui_used.json")
    state["mgr"] = ConversationManager(state["factory"])
    return "Mnemonic loaded successfully"


def create_shared_secret():
    secret = secrets.token_bytes(32)
    state["shared_secret"] = secret
    return to_hex(secret)


def set_shared_secret(hex_secret: str):
    try:
        secret = bytes.fromhex(hex_secret.replace("0x", ""))
        if len(secret) != 32:
            return "Secret must be 32 bytes"
        state["shared_secret"] = secret
        return "Shared secret set"
    except Exception as e:
        return f"Error: {e}"


def start_conversation():
    if not state.get("mgr") or not state.get("shared_secret"):
        return "Load mnemonic and set shared secret first", "", ""
    conv = state["mgr"].start_conversation(state["shared_secret"])
    state["conv"] = conv
    signers = "\n".join(conv.my_signers)
    return (
        f"Conversation started\nRendezvous D: {conv.rendezvous_d}",
        conv.rendezvous_d,
        signers,
    )


def sign_message(message: str, use_encryption: bool):
    if not state.get("conv") or not state.get("mgr"):
        return "Start a conversation first", "", ""

    conv = state["conv"]
    try:
        signer, acct = state["mgr"].next_signer(conv)  # fresh one-time signer
        payload_hash, metadata, signature = prepare_and_sign(
            acct, signer, conv.rendezvous_d, message,
            state["shared_secret"], use_encryption=use_encryption,
        )
        if not verify_record(signer, conv.rendezvous_d, payload_hash, metadata, signature):
            return "Local signature check failed", "", ""
        call = build_record_signature_call(signer, conv.rendezvous_d, payload_hash, signature, metadata)
        call_json = json.dumps(
            {
                "to": call["to"],
                "chainId": CHAIN_ID,
                "function": call["function"],
                "signer": call["args"][0],
                "intendedTo": call["args"][1],
                "payloadHash": to_hex(call["args"][2]),
                "signature": to_hex(call["args"][3]),
                "metadata": call["args"][4],
            },
            indent=2,
        )
        return f"Signed with one-time signer {signer}\nMetadata: {metadata}", to_hex(payload_hash), call_json
    except Exception as e:
        return f"Error: {e}", "", ""


def decrypt_record(metadata: str, payload_hash_hex: str):
    if not state.get("shared_secret"):
        return "Set the shared secret first"
    try:
        ph = bytes.fromhex(payload_hash_hex.strip().replace("0x", ""))
        return read_record(metadata.strip(), ph, state["shared_secret"])
    except Exception as e:
        return f"Could not decrypt (wrong secret, or not a message for this conversation): {type(e).__name__}"


def earn_credit():
    uid = "local_user"
    state["credits"].earn(uid)
    return f"Earned 1 gas credit. Balance: {state['credits'].balance(uid)}"


def credit_balance():
    return f"Current gas credits: {state['credits'].balance('local_user')}"


# ---------- Gradio UI ----------
with gr.Blocks(title="SOS 69069 Privacy Messenger", theme=gr.themes.Soft()) as demo:
    gr.Markdown(
        f"""
        # SOS 69069 Privacy Messenger
        **Contract:** `{CONTRACT_ADDRESS}`  
        Messages are carried inside the 64-character `metadata` field.  
        Signers never pay gas. Community relayers + reciprocal credits handle submission.
        """
    )

    with gr.Tab("1. Wallet"):
        mnemonic_out = gr.Textbox(label="Mnemonic (keep secret)", lines=2)
        with gr.Row():
            btn_gen = gr.Button("Generate new mnemonic")
            btn_set = gr.Button("Load mnemonic")
        mnemonic_in = gr.Textbox(label="Paste existing mnemonic", lines=2)
        status_wallet = gr.Textbox(label="Status")

        btn_gen.click(generate_mnemonic, outputs=mnemonic_out)
        btn_set.click(set_mnemonic, inputs=mnemonic_in, outputs=status_wallet)

    with gr.Tab("2. Shared Secret"):
        secret_out = gr.Textbox(label="Shared secret (hex)")
        with gr.Row():
            btn_new_secret = gr.Button("Generate new shared secret")
            btn_set_secret = gr.Button("Set shared secret")
        secret_in = gr.Textbox(label="Paste shared secret (hex)")
        status_secret = gr.Textbox(label="Status")

        btn_new_secret.click(create_shared_secret, outputs=secret_out)
        btn_set_secret.click(set_shared_secret, inputs=secret_in, outputs=status_secret)

    with gr.Tab("3. Conversation"):
        btn_start = gr.Button("Start conversation (A + B → D)", variant="primary")
        conv_status = gr.Textbox(label="Status", lines=3)
        d_out = gr.Textbox(label="Rendezvous address D")
        signers_out = gr.Textbox(label="My one-time signer addresses", lines=4)

        btn_start.click(start_conversation, outputs=[conv_status, d_out, signers_out])

    with gr.Tab("4. Sign Message"):
        msg_in = gr.Textbox(
            label=f"Message (≤{MAX_PLAINTEXT_BYTES} bytes encrypted, ≤{MAX_METADATA_LENGTH} bytes plain)",
            lines=2,
            max_lines=3,
        )
        encrypt_check = gr.Checkbox(label="Encrypt under shared secret", value=True)
        btn_sign = gr.Button("Sign message → produce Record", variant="primary")
        sign_status = gr.Textbox(label="Status", lines=2)
        payload_out = gr.Textbox(label="payloadHash")
        call_out = gr.Code(label="Ready-to-submit call (give this to any relayer / credit holder)", language="json")

        btn_sign.click(
            sign_message,
            inputs=[msg_in, encrypt_check],
            outputs=[sign_status, payload_out, call_out],
        )

    with gr.Tab("5. Read a record"):
        gr.Markdown("Paste `metadata` and `payloadHash` from a `SignatureRecorded` event on your D.")
        meta_in = gr.Textbox(label="metadata")
        ph_in = gr.Textbox(label="payloadHash (0x…)")
        btn_dec = gr.Button("Decrypt")
        dec_out = gr.Textbox(label="Message")
        btn_dec.click(decrypt_record, inputs=[meta_in, ph_in], outputs=dec_out)

    with gr.Tab("6. Gas Credits"):
        gr.Markdown("Local reciprocal gas-credit stub. In production this is privacy-preserving and global.")
        btn_earn = gr.Button("Simulate: I paid gas for a stranger → earn 1 credit")
        btn_bal = gr.Button("Show my credit balance")
        credit_status = gr.Textbox(label="Credits")

        btn_earn.click(earn_credit, outputs=credit_status)
        btn_bal.click(credit_balance, outputs=credit_status)

    gr.Markdown(
        """
        ---
        **How to use with a real relayer**  
        1. Copy the JSON from the “Sign Message” tab.  
        2. Any unrelated user (or community relayer) can call `recordSignature` on the contract with those arguments and pay the gas.  
        3. The 64-char metadata field on-chain now carries your message.
        """
    )


if __name__ == "__main__":
    demo.launch()
