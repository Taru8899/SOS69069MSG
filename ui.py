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
from message_engine import prepare_and_sign
from submission import build_record_signature_call
from gas_credits import GasCreditBook
from config import CONTRACT_ADDRESS, MAX_METADATA_LENGTH

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
    Account.enable_unaudited_hdwallet_features()
    mnemonic = Account.create().key.hex()  # placeholder – better use proper BIP39
    # Simple demo mnemonic generator
    from eth_account.hdaccount import generate_mnemonic
    mnemonic = generate_mnemonic(12)
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
    if not state.get("conv") or not state.get("mnemonic"):
        return "Start a conversation first", "", ""
    if len(message.encode("utf-8")) > MAX_METADATA_LENGTH and not use_encryption:
        return f"Message too long for plain metadata (max {MAX_METADATA_LENGTH} chars)", "", ""

    conv = state["conv"]
    signer = conv.my_signers[0]
    # Derive the account for the first signer (index 0)
    acct = Account.from_mnemonic(state["mnemonic"], account_path="m/44'/60'/2'/0/0")

    try:
        payload_hash, metadata, signature = prepare_and_sign(
            acct,
            signer,
            conv.rendezvous_d,
            message,
            state["shared_secret"],
            use_encryption=use_encryption,
        )
        call = build_record_signature_call(
            signer, conv.rendezvous_d, payload_hash, signature, metadata
        )
        call_json = json.dumps(
            {
                "to": call["to"],
                "function": call["function"],
                "signer": call["args"][0],
                "intendedTo": call["args"][1],
                "payloadHash": to_hex(call["args"][2]),
                "signature": to_hex(call["args"][3]),
                "metadata": call["args"][4],
            },
            indent=2,
        )
        return (
            f"Signed successfully\nMetadata (message carrier): {metadata}",
            to_hex(payload_hash),
            call_json,
        )
    except Exception as e:
        return f"Error: {e}", "", ""


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
            label=f"Message (will be packed into ≤{MAX_METADATA_LENGTH} char metadata)",
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

    with gr.Tab("5. Gas Credits"):
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
