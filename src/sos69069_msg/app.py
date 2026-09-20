"""
sos69069 msg — native (Toga) UI. Android via Briefcase; desktop via `briefcase dev`.

Tabs: Setup · Send · Inbox · Relay
"""

import asyncio
import json
import os
import secrets
import traceback
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW, NONE, PACK

from .address_factory import AddressFactory, generate_seed
from .config import CHAIN_ID, CONTRACT_ADDRESS
from .conversation import ConversationManager
from .crypto_utils import MAX_PLAINTEXT_BYTES
from .eip712 import verify_record
from .message_engine import prepare_and_sign
from .reader import Inbox, sync
from .relayer import parse_record, submit
from .rpc import RpcClient
from .submission import build_record_signature_call

DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"   # any mainnet https RPC works
DEFAULT_MAX_FEE_GWEI = 50.0


def _pad():
    """Fresh Pack per widget. Toga 0.5 renamed padding -> margin."""
    try:
        return Pack(margin=6)
    except (TypeError, AttributeError):
        return Pack(padding=6)


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip().removeprefix("0x"))


class SOS69069MsgApp(toga.App):
    def startup(self):
        try:
            self._build()
        except Exception:
            self._show_error(traceback.format_exc())

    def _show_error(self, text: str):
        """Never crash silently: show the traceback on screen (and save it to crash.log)."""
        try:
            (Path(self.paths.data) / "crash.log").write_text(text)
        except Exception:
            pass
        box = toga.Box(style=Pack(direction=COLUMN), children=[
            toga.Label("sos69069 msg failed to start. Screenshot this and send it:"),
            toga.MultilineTextInput(readonly=True, value=text, style=Pack(flex=1)),
        ])
        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = box
        self.main_window.show()

    def _build(self):
        self.data_dir = Path(self.paths.data)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.seed_file = self.data_dir / "seed.hex"
        self.settings_file = self.data_dir / "settings.json"
        self.mgr = self.conv = self.secret = self.inbox = self.relayer = None
        self.settings = self._load_settings()
        self._load_seed()

        # ---------------- Setup tab ----------------
        self.seed_status = toga.Label("", style=_pad())
        self.seed_out = toga.MultilineTextInput(readonly=True, placeholder="Seed appears here once — back it up", style=Pack(height=70))
        self.seed_in = toga.TextInput(placeholder="Paste 64-hex seed to import", style=_pad())
        self.secret_in = toga.TextInput(placeholder="Shared secret (64 hex)", style=_pad())
        self.conv_out = toga.MultilineTextInput(readonly=True, style=Pack(height=110))
        self.rpc_in = toga.TextInput(value=self.settings["rpc_url"], style=_pad())
        self.cap_in = toga.TextInput(value=str(self.settings["max_fee_gwei"]), style=_pad())
        self.net_status = toga.Label("", style=_pad())

        setup = toga.Box(style=Pack(direction=COLUMN), children=[
            toga.Label("1. Identity", style=_pad()),
            self.seed_status,
            toga.Button("Create new identity", on_press=self.create_identity, style=_pad()),
            self.seed_out,
            self.seed_in,
            toga.Button("Import seed", on_press=self.import_seed, style=_pad()),
            toga.Label("2. Shared secret (exchange it out-of-band)", style=_pad()),
            self.secret_in,
            toga.Button("Generate new secret", on_press=self.gen_secret, style=_pad()),
            toga.Label("3. Conversation", style=_pad()),
            toga.Button("Start conversation", on_press=self.start_conversation, style=_pad()),
            self.conv_out,
            toga.Label("4. Network (Ethereum mainnet)", style=_pad()),
            toga.Label("RPC URL (https). The provider sees your IP and queries.", style=_pad()),
            self.rpc_in,
            toga.Label("Max gas fee you'll pay (gwei)", style=_pad()),
            self.cap_in,
            toga.Button("Save network settings", on_press=self.save_network, style=_pad()),
            self.net_status,
        ])

        # ---------------- Send tab ----------------
        self.msg_in = toga.TextInput(placeholder=f"Message (≤{MAX_PLAINTEXT_BYTES} bytes encrypted)", style=_pad())
        self.encrypt_sw = toga.Switch("Encrypt", value=True, style=_pad())
        self.send_status = toga.Label("", style=_pad())
        self.send_out = toga.MultilineTextInput(readonly=True, style=Pack(height=240))
        send = toga.Box(style=Pack(direction=COLUMN), children=[
            self.msg_in, self.encrypt_sw,
            toga.Button("Sign message", on_press=self.sign_message, style=_pad()),
            self.send_status,
            toga.Label("Signed record. Share it with anyone who can submit it, or submit it yourself on the Relay tab:", style=_pad()),
            self.send_out,
        ])

        # ---------------- Inbox tab ----------------
        self.from_in = toga.TextInput(placeholder="Scan from block (optional)", style=_pad())
        self.inbox_status = toga.Label("", style=_pad())
        self.inbox_out = toga.MultilineTextInput(readonly=True, style=Pack(height=360))
        inbox = toga.Box(style=Pack(direction=COLUMN), children=[
            toga.Button("Refresh from chain", on_press=self.refresh_inbox, style=_pad()),
            self.from_in,
            self.inbox_status,
            self.inbox_out,
        ])

        # ---------------- Relay tab ----------------
        self.relayer_label = toga.Label("", style=_pad())
        self.balance_label = toga.Label("", style=_pad())
        self.relay_in = toga.MultilineTextInput(placeholder="Paste a signed record JSON here", style=Pack(height=200))
        self.relay_status = toga.Label("", style=_pad())
        relay = toga.Box(style=Pack(direction=COLUMN), children=[
            toga.Label("Your relayer address (send it a little ETH; it pays gas):", style=_pad()),
            self.relayer_label,
            toga.Button("Check balance", on_press=self.check_balance, style=_pad()),
            self.balance_label,
            toga.Label("Record to submit (yours, or a stranger's):", style=_pad()),
            self.relay_in,
            toga.Button("Submit to Ethereum", on_press=self.submit_record, style=_pad()),
            self.relay_status,
        ])

        # Simple button navigation (avoids the Android OptionContainer); each tab is its own
        # ScrollContainer and inactive ones are hidden with display=none.
        self.tabs = {}
        for i, (name, box) in enumerate([("Setup", setup), ("Send", send),
                                         ("Inbox", inbox), ("Relay", relay)]):
            self.tabs[name] = toga.ScrollContainer(
                content=box, horizontal=False,
                style=Pack(flex=1, display=PACK if i == 0 else NONE))
        nav = toga.Box(style=Pack(direction=ROW), children=[
            toga.Button(name, on_press=self._nav(name), style=Pack(flex=1)) for name in self.tabs])
        root = toga.Box(style=Pack(direction=COLUMN), children=[nav, *self.tabs.values()])
        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = root
        self.main_window.show()
        self._refresh_seed_status()

    def _nav(self, name):
        def handler(widget, **kwargs):
            for n, sc in self.tabs.items():
                sc.style.display = PACK if n == name else NONE
        return handler

    # ------------------------------------------------------------ settings
    def _load_settings(self):
        s = {"rpc_url": DEFAULT_RPC, "max_fee_gwei": DEFAULT_MAX_FEE_GWEI}
        if self.settings_file.exists():
            try:
                s.update(json.loads(self.settings_file.read_text()))
            except Exception:
                pass
        return s

    def save_network(self, widget, **kwargs):
        try:
            RpcClient(self.rpc_in.value)  # validates https
            cap = float(self.cap_in.value)
            if cap <= 0:
                raise ValueError("cap must be > 0")
            self.settings = {"rpc_url": self.rpc_in.value.strip(), "max_fee_gwei": cap}
            self.settings_file.write_text(json.dumps(self.settings))
            self.net_status.text = "Saved ✔"
        except Exception as e:
            self.net_status.text = f"Error: {e}"

    def _rpc(self) -> RpcClient:
        return RpcClient(self.settings["rpc_url"])

    # ------------------------------------------------------------ identity
    def _load_seed(self):
        if self.seed_file.exists():
            self._set_seed(_from_hex(self.seed_file.read_text()), save=False)

    def _set_seed(self, seed: bytes, save: bool = True):
        if len(seed) != 32:
            raise ValueError("Seed must be 32 bytes (64 hex characters)")
        if save:
            self.seed_file.write_text(seed.hex())
            try:
                os.chmod(self.seed_file, 0o600)
            except OSError:
                pass
        factory = AddressFactory(seed, str(self.data_dir / "signer_counter.json"))
        self.mgr = ConversationManager(factory)
        self.relayer = factory.relayer_key()
        self.conv = self.inbox = None

    def _refresh_seed_status(self):
        self.seed_status.text = "Identity loaded ✔" if self.mgr else "No identity yet"
        self.relayer_label.text = self.relayer.address if self.relayer else "(create an identity first)"

    def create_identity(self, widget, **kwargs):
        seed = generate_seed()
        self._set_seed(seed)
        self.seed_out.value = seed.hex()
        self._refresh_seed_status()

    def import_seed(self, widget, **kwargs):
        try:
            self._set_seed(_from_hex(self.seed_in.value))
            self.seed_in.value = ""
        except Exception as e:
            self.seed_status.text = f"Error: {e}"
            return
        self._refresh_seed_status()

    # ------------------------------------------------------ secret / conv
    def gen_secret(self, widget, **kwargs):
        self.secret_in.value = secrets.token_bytes(32).hex()

    def start_conversation(self, widget, **kwargs):
        try:
            if not self.mgr:
                raise ValueError("Create or import an identity first")
            secret = _from_hex(self.secret_in.value)
            self.conv = self.mgr.start_conversation(secret)
            self.secret = secret
            self.inbox = Inbox(str(self.data_dir / f"inbox_{self.conv.rendezvous_d[2:10]}.json"))
            self.inbox_out.value = self.inbox.render()
            self.conv_out.value = (
                f"Rendezvous D:\n{self.conv.rendezvous_d}\n\n"
                f"Chain: Ethereum mainnet ({CHAIN_ID})\nContract: {CONTRACT_ADDRESS}"
            )
        except Exception as e:
            self.conv_out.value = f"Error: {e}"

    # ---------------------------------------------------------------- send
    def sign_message(self, widget, **kwargs):
        try:
            if not self.conv:
                raise ValueError("Start a conversation first")
            key = self.mgr.next_signer(self.conv)  # fresh one-time signer
            ph, meta, sig = prepare_and_sign(
                key, self.conv.rendezvous_d, self.msg_in.value, self.secret,
                use_encryption=self.encrypt_sw.value,
            )
            if not verify_record(key.address, self.conv.rendezvous_d, ph, meta, sig):
                raise RuntimeError("Local signature check failed")
            call = build_record_signature_call(key.address, self.conv.rendezvous_d, ph, sig, meta)
            record = json.dumps({
                "to": call["to"], "chainId": CHAIN_ID, "function": call["function"],
                "signer": call["args"][0], "intendedTo": call["args"][1],
                "payloadHash": _hex(ph), "signature": _hex(sig), "metadata": meta,
            }, indent=2)
            self.send_out.value = record
            self.relay_in.value = record          # ready to submit on the Relay tab
            self.send_status.text = f"Signed ✔ (one-time signer {key.address[:10]}…)"
            self.msg_in.value = ""
        except Exception as e:
            self.send_status.text = f"Error: {e}"

    # --------------------------------------------------------------- inbox
    async def refresh_inbox(self, widget, **kwargs):
        if not self.conv or not self.inbox:
            self.inbox_status.text = "Start a conversation first"
            return
        self.inbox_status.text = "Scanning…"
        try:
            frm = int(self.from_in.value) if self.from_in.value.strip() else None
            rpc, conv, inbox, secret = self._rpc(), self.conv, self.inbox, self.secret
            new, noise = await asyncio.to_thread(
                sync, rpc, conv.rendezvous_d, secret, inbox, frm)
            self.inbox_out.value = inbox.render()
            self.inbox_status.text = (f"{new} new message(s). {noise} record(s) on D were not from "
                                      f"this conversation. Scanned to block {inbox.last_block}.")
        except Exception as e:
            self.inbox_status.text = f"Error: {e}"

    # --------------------------------------------------------------- relay
    async def check_balance(self, widget, **kwargs):
        if not self.relayer:
            self.balance_label.text = "Create an identity first"
            return
        try:
            wei = await asyncio.to_thread(self._rpc().balance, self.relayer.address)
            self.balance_label.text = f"{wei / 1e18:.6f} ETH"
        except Exception as e:
            self.balance_label.text = f"Error: {e}"

    async def submit_record(self, widget, **kwargs):
        if not self.relayer:
            self.relay_status.text = "Create an identity first"
            return
        try:
            rec = parse_record(self.relay_in.value)   # validates + verifies signature locally
            self.relay_status.text = "Submitting…"
            rpc, relayer, cap = self._rpc(), self.relayer, float(self.settings["max_fee_gwei"])
            tx = await asyncio.to_thread(submit, rpc, relayer, rec, cap)
            self.relay_status.text = f"Sent ✔\nhttps://etherscan.io/tx/{tx}"
        except Exception as e:
            self.relay_status.text = f"Error: {e}"


def main():
    return SOS69069MsgApp("sos69069 msg", "org.sos69069.msg")
