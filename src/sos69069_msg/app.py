"""
SOS69069 MSG — CHECK · SEND · RELAY · SETUP

- Random (or pasted) D is the only common ground
- Plain 64-char public metadata only (no encryption)
- Any private key can pay gas on RELAY
- Short codes on every message
"""

import asyncio
import json
import os
import secrets
import time
import traceback
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from .address_factory import AddressFactory, generate_seed
from .config import CHAIN_ID, CONTRACT_ADDRESS, MAX_METADATA_LENGTH
from .conversation import ConversationManager
from .eip712 import verify_record
from .logo import logo_bytes
from .message_engine import prepare_and_sign, short_code
from .reader import Inbox, sync
from .relayer import parse_record, submit
from .rpc import RpcClient
from .submission import build_record_signature_call
from .ethcrypto import KeyPair

APP_NAME = "SOS69069 MSG"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
DEFAULT_MAX_FEE_GWEI = 50.0

BG = "#090E0A"
FIELD = "#242F27"
PANEL = "#141A16"
GREEN = "#05AA34"
GREY = "#2F3B35"
TAB = "#575757"
TAB_LINE = "#4FA3D1"
TXT = "#FFFFFF"
MUTED = "#C9D1CD"


def _pack(pad=None, **kw):
    if pad is not None:
        for key in ("margin", "padding"):
            try:
                return Pack(**{key: pad}, **kw)
            except Exception:
                continue
    return Pack(**kw)


def _col(children, **kw):
    return toga.Box(style=_pack(direction=COLUMN, background_color=BG, **kw), children=children)


def _row(children, **kw):
    return toga.Box(style=_pack(direction=ROW, background_color=BG, **kw), children=children)


def _label(text="", muted=True, size=14, bold=False, pad=(10, 16, 2, 16), **kw):
    extra = {"font_weight": "bold"} if bold else {}
    return toga.Label(text, style=_pack(pad=pad, color=MUTED if muted else TXT,
                                        background_color=BG, font_size=size, **extra, **kw))


def _title(text):
    return _label(text, muted=False, size=17, bold=True, pad=(18, 16, 4, 16))


def _input(value="", placeholder=""):
    return toga.TextInput(value=value, placeholder=placeholder,
                          style=_pack(pad=(4, 16, 6, 16), color=TXT, background_color=FIELD,
                                      font_size=16, height=52))


def _panel(height=120, placeholder=""):
    return toga.MultilineTextInput(readonly=True, value=placeholder,
                                   style=_pack(pad=(4, 16, 6, 16), color=TXT,
                                               background_color=PANEL, font_size=14, height=height))


def _button(text, handler, primary=True):
    bg = GREEN if primary else GREY
    return toga.Button(text, on_press=handler,
                       style=_pack(pad=(8, 16, 8, 16), color=TXT, background_color=bg,
                                   font_size=16, height=48))


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip().removeprefix("0x"))


class SOS69069MsgApp(toga.App):
    def startup(self):
        try:
            self._real_startup()
        except Exception:
            err = traceback.format_exc()
            try:
                log = Path(getattr(self.paths, "data", ".") or ".") / "crash.txt"
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_text(err)
            except Exception:
                pass
            self.main_window = toga.MainWindow(title="Startup Crash")
            box = toga.Box(style=_pack(direction=COLUMN, margin=10))
            box.add(toga.Label("The app crashed during startup. Share this error:"))
            box.add(toga.MultilineTextInput(value=err, readonly=True,
                                            style=_pack(flex=1, height=400)))
            self.main_window.content = box
            self.main_window.show()

    def _real_startup(self):
        self.data_dir = Path(self.paths.data)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.seed_file = self.data_dir / "seed.hex"
        self.settings_file = self.data_dir / "settings.json"
        self.mgr = self.conv = self.inbox = self.relayer = None
        self.last_tx_link = ""
        self._refreshing = False
        self._refresh_started = 0.0
        self.settings = self._load_settings()
        self._load_seed()          # auto-creates seed if missing

        # ---------- CHECK ----------
        self.d_in = _input(placeholder="D address (0x…)")
        self.check_status = _label("", muted=False)
        self.messages_out = _panel(360)
        self.from_in = _input(placeholder="Scan from block (optional)")
        check = _col([
            _title("CHECK"),
            _label("Enter any D address and press CHECK. Leave as-is for the current conversation."),
            self.d_in,
            _button("CHECK", self.do_check),
            self.check_status,
            _label("Messages", muted=False, bold=True, size=16),
            self.messages_out,
            _button("Send", self.goto_send, primary=False),
            self.from_in,
        ])

        # ---------- SEND ----------
        self.msg_in = _input(placeholder=f"Message (≤{MAX_METADATA_LENGTH} characters)")
        self.reply_code_in = _input(placeholder="Optional short code to answer (#A3F2)")
        self.send_status = _label("", muted=False)
        self.signed_out = _panel(200)
        send = _col([
            _title("SEND"),
            _label("Plain public text only. Max 64 characters. No encryption."),
            self.msg_in,
            _label("Optional short code of the message you are answering"),
            self.reply_code_in,
            _button("Sign", self.sign_message),
            self.send_status,
            _label("Signed data", muted=False, bold=True),
            self.signed_out,
            _button("Send → Relay", self.goto_relay),
        ])

        # ---------- RELAY ----------
        self.relayer_in = _input(placeholder="Relayer address OR private key (64 hex)")
        self.relayer_note = _label("", size=13)
        self.balance_label = _label("", muted=False)
        self.relay_in = toga.MultilineTextInput(
            placeholder="Signed record JSON",
            style=_pack(pad=(6, 16, 6, 16), color=TXT, background_color=FIELD,
                        font_size=14, height=200))
        self.relay_status = _label("", muted=False)
        relay = _col([
            _title("RELAY"),
            _label("Paste any private key to pay gas, or leave the default address."),
            self.relayer_in,
            self.relayer_note,
            _button("Check balance", self.check_balance, primary=False),
            self.balance_label,
            _label("Signed record to submit"),
            self.relay_in,
            _button("Submit to Ethereum", self.submit_record),
            self.relay_status,
            _button("Copy tx link", self._copier(lambda: self.last_tx_link, "tx link",
                                                 self.relay_status), primary=False),
        ])

        # ---------- SETUP ----------
        self.seed_status = _label("", muted=False)
        self.seed_out = _panel(70, "Seed (auto-created). Back it up if you want.")
        self.seed_in = _input(placeholder="Paste 64-hex seed to import")
        self.conv_out = _panel(120)
        self.rpc_in = _input(value=self.settings["rpc_url"])
        self.cap_in = _input(value=str(self.settings["max_fee_gwei"]))
        self.net_status = _label("", muted=False)
        self.copy_status = _label("", muted=False)
        setup = _col([
            _title("SETUP"),
            _label("Identity is created automatically so you can sign. You only need to touch this "
                   "if you want to back up or restore a seed."),
            self.seed_status,
            self.seed_out,
            _button("Copy seed", self._copier(
                lambda: self.seed_out.value or (
                    self.seed_file.read_text() if self.seed_file.exists() else ""),
                "seed", self.copy_status), primary=False),
            self.copy_status,
            self.seed_in,
            _button("Import seed", self.import_seed, primary=False),
            _title("Conversation"),
            _button("Start new conversation (new random D)", self.start_new_conversation),
            self.conv_out,
            _button("Copy current D", self._copier(
                lambda: self.conv.rendezvous_d if self.conv else "", "D", self.copy_status),
                primary=False),
            _title("Network"),
            self.rpc_in,
            _label("Max gas fee (gwei)"),
            self.cap_in,
            _button("Save network settings", self.save_network, primary=False),
            self.net_status,
        ])

        # Tab order: CHECK · SEND · RELAY · SETUP
        bodies = {"CHECK": check, "SEND": send, "RELAY": relay, "SETUP": setup}
        self.pages = {}
        for name, body in bodies.items():
            scroller = toga.ScrollContainer(content=body, horizontal=False,
                                            style=_pack(flex=1, background_color=BG))
            self.pages[name] = _col([self._header(name, list(bodies)), scroller], flex=1)

        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = self.pages["CHECK"]
        self.main_window.show()
        self._hide_title_bar()
        self._refresh_seed_status()
        # Auto-start a conversation so D is ready
        if self.mgr and not self.conv:
            self.start_new_conversation(None)

    # ------------------------------------------------------------------ header / nav
    def _header(self, active: str, names: list):
        def make_tab(n):
            def go(widget, **kw):
                self.main_window.content = self.pages[n]
            color = TAB_LINE if n == active else TAB
            return toga.Button(n, on_press=go,
                               style=_pack(pad=6, color=TXT, background_color=color,
                                           font_size=14, flex=1, height=40))
        try:
            logo = toga.ImageView(toga.Image(data=logo_bytes()),
                                  style=_pack(width=36, height=36, pad=(8, 8, 4, 16)))
        except Exception:
            logo = toga.Label("69069", style=_pack(pad=(8, 8, 4, 16), color=GREEN, font_size=16))
        top = _row([logo, _label(APP_NAME, muted=False, size=16, bold=True, pad=(12, 8, 4, 4))])
        tabs = _row([make_tab(n) for n in names])
        return _col([top, tabs])

    def _hide_title_bar(self):
        try:
            from java import jclass
            activity = self._impl.native
            activity.getSupportActionBar().hide()
        except Exception:
            try:
                activity.requestWindowFeature(1)  # FEATURE_NO_TITLE
            except Exception:
                pass

    def goto_send(self, widget, **kw):
        self.main_window.content = self.pages["SEND"]

    def goto_relay(self, widget, **kw):
        if self.signed_out.value:
            self.relay_in.value = self.signed_out.value
        self.main_window.content = self.pages["RELAY"]

    # ------------------------------------------------------------------ clipboard
    def _copy(self, text: str) -> bool:
        try:
            self.clipboard.set_text(text)
            return True
        except Exception:
            pass
        try:
            from java import jclass
            Context = jclass("android.content.Context")
            ClipData = jclass("android.content.ClipData")
            cm = self._impl.native.getSystemService(Context.CLIPBOARD_SERVICE)
            cm.setPrimaryClip(ClipData.newPlainText("sos69069", text))
            return True
        except Exception:
            return False

    def _copier(self, getter, what: str, status):
        def handler(widget, **kwargs):
            t = getter()
            if not t:
                status.text = f"Nothing to copy ({what})"
                return
            status.text = f"Copied {what} ✔" if self._copy(t) else f"Could not copy {what}"
        return handler

    # ------------------------------------------------------------------ settings / seed
    def _load_settings(self):
        s = {"rpc_url": DEFAULT_RPC, "max_fee_gwei": DEFAULT_MAX_FEE_GWEI}
        if self.settings_file.exists():
            try:
                s.update(json.loads(self.settings_file.read_text()))
            except Exception:
                pass
        return s

    def _save_settings(self):
        self.settings_file.write_text(json.dumps(self.settings))

    def save_network(self, widget, **kwargs):
        try:
            RpcClient(self.rpc_in.value)
            cap = float(self.cap_in.value)
            if cap <= 0:
                raise ValueError("cap must be > 0")
            self.settings = {"rpc_url": self.rpc_in.value.strip(), "max_fee_gwei": cap}
            self._save_settings()
            self.net_status.text = "Saved ✔"
        except Exception as e:
            self.net_status.text = f"Error: {e}"

    def _rpc(self) -> RpcClient:
        return RpcClient(self.settings["rpc_url"])

    def _load_seed(self):
        if self.seed_file.exists():
            self._set_seed(_from_hex(self.seed_file.read_text()), save=False)
        else:
            # Auto-create so the user never has to press "Create identity"
            self._set_seed(generate_seed(), save=True)

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
        self.relayer = factory.relayer_key(0)
        self.conv = self.inbox = None

    def _refresh_seed_status(self):
        self.seed_status.text = "Identity ready ✔ (auto)" if self.mgr else "No identity"
        if self.seed_file.exists():
            self.seed_out.value = self.seed_file.read_text()
        if self.relayer:
            self.relayer_in.value = self.relayer.address
            self.relayer_note.text = "Default relayer (seed-derived). Paste any private key to override."

    def import_seed(self, widget, **kwargs):
        try:
            self._set_seed(_from_hex(self.seed_in.value))
            self.seed_in.value = ""
            self._refresh_seed_status()
            self.start_new_conversation(None)
        except Exception as e:
            self.seed_status.text = f"Error: {e}"

    # ------------------------------------------------------------------ conversation / D
    def start_new_conversation(self, widget, **kwargs):
        try:
            if not self.mgr:
                raise ValueError("Identity missing")
            self.conv = self.mgr.start_conversation()          # brand-new random D
            self.inbox = Inbox(str(self.data_dir / f"inbox_{self.conv.rendezvous_d[2:10]}.json"))
            self.d_in.value = self.conv.rendezvous_d
            self.messages_out.value = self.inbox.render(self.conv.rendezvous_d)
            self.conv_out.value = (
                f"New D ready:\n{self.conv.rendezvous_d}\n\n"
                f"Share this address with the other person.\n"
                f"Contract: {CONTRACT_ADDRESS}"
            )
            if self.relayer:
                self.relayer_in.value = self.relayer.address
            self.check_status.text = "New conversation started ✔"
        except Exception as e:
            self.conv_out.value = f"Error: {e}"

    # ------------------------------------------------------------------ CHECK
    async def do_check(self, widget, **kwargs):
        d = (self.d_in.value or "").strip()
        if not d:
            self.check_status.text = "Enter a D address first"
            return
        # Switch conversation context to the typed D if different
        try:
            if not self.mgr:
                raise ValueError("Identity missing")
            if not self.conv or self.conv.rendezvous_d.lower() != d.lower():
                self.conv = self.mgr.start_conversation(d=d)
                self.inbox = Inbox(str(self.data_dir / f"inbox_{d[2:10]}.json"))
        except Exception as e:
            self.check_status.text = f"Error: {e}"
            return

        if self._refreshing and time.monotonic() - self._refresh_started < 90:
            self.check_status.text = "Already scanning…"
            return
        self._refreshing, self._refresh_started = True, time.monotonic()
        self.check_status.text = "Scanning…"
        loop = asyncio.get_running_loop()

        def progress(msg):
            loop.call_soon_threadsafe(lambda: setattr(self.check_status, "text", msg))

        try:
            frm = int(self.from_in.value) if self.from_in.value.strip() else None
            rpc, inbox = self._rpc(), self.inbox
            new = await asyncio.to_thread(sync, rpc, d, inbox, frm, progress)
            mine = self.mgr.factory.my_signer_addresses() if self.mgr else ()
            self.messages_out.value = inbox.render(d, mine)
            self.check_status.text = (
                f"{new} new message(s). Scanned to block {inbox.last_block}."
                if inbox.last_block is not None else "Done."
            )
        except Exception as e:
            self.check_status.text = f"Error: {e}"
        finally:
            self._refreshing = False

    # ------------------------------------------------------------------ SEND
    def sign_message(self, widget, **kwargs):
        try:
            if not self.conv:
                raise ValueError("Start a conversation first (SETUP → Start new conversation)")
            text = (self.msg_in.value or "").strip()
            if not text:
                raise ValueError("Type a message first")
            key = self.mgr.next_signer(self.conv)
            ph, meta, sig = prepare_and_sign(
                key, self.conv.rendezvous_d, text,
                reply_code=self.reply_code_in.value or "",
            )
            if not verify_record(key.address, self.conv.rendezvous_d, ph, meta, sig):
                raise RuntimeError("Local signature check failed")
            call = build_record_signature_call(
                key.address, self.conv.rendezvous_d, ph, sig, meta)
            record = json.dumps({
                "to": call["to"], "chainId": CHAIN_ID, "function": call["function"],
                "signer": call["args"][0], "intendedTo": call["args"][1],
                "payloadHash": _hex(ph), "signature": _hex(sig), "metadata": meta,
            }, indent=2)
            self.signed_out.value = record
            self.relay_in.value = record
            if self.inbox:
                self.inbox.add_pending(_hex(ph), meta)
                self.messages_out.value = self.inbox.render(
                    self.conv.rendezvous_d,
                    self.mgr.factory.my_signer_addresses())
            code = short_code(_hex(ph))
            self.send_status.text = (
                f"Signed ✔  #{code}  (not on chain yet — open RELAY and Submit)"
            )
            self.msg_in.value = ""
            self.reply_code_in.value = ""
        except Exception as e:
            self.send_status.text = f"Error: {e}"

    # ------------------------------------------------------------------ RELAY helpers
    def _active_relayer(self) -> KeyPair:
        """Prefer a pasted private key; otherwise the seed-derived relayer."""
        raw = (self.relayer_in.value or "").strip().removeprefix("0x")
        if len(raw) == 64:
            try:
                return KeyPair.from_private_key(bytes.fromhex(raw))
            except Exception as e:
                raise ValueError(f"Invalid private key: {e}") from e
        if not self.relayer:
            raise ValueError("No relayer — identity missing")
        return self.relayer

    async def check_balance(self, widget, **kwargs):
        try:
            relayer = self._active_relayer()
            wei = await asyncio.to_thread(self._rpc().balance, relayer.address)
            self.balance_label.text = f"{wei / 1e18:.6f} ETH   {relayer.address[:10]}…"
        except Exception as e:
            self.balance_label.text = f"Error: {e}"

    async def submit_record(self, widget, **kwargs):
        try:
            relayer = self._active_relayer()
            rec = parse_record(self.relay_in.value)
            self.relay_status.text = "Submitting…"
            rpc = self._rpc()
            cap = float(self.settings["max_fee_gwei"])
            tx = await asyncio.to_thread(submit, rpc, relayer, rec, cap)
            self.last_tx_link = f"https://etherscan.io/tx/{tx}"
            self.relay_status.text = f"Sent ✔\n{self.last_tx_link}"
            # Mark pending as submitted
            ph = rec.get("payloadHash", "")
            if self.inbox and ph:
                self.inbox.mark_submitted(ph, tx)
                self.messages_out.value = self.inbox.render(
                    self.conv.rendezvous_d if self.conv else "",
                    self.mgr.factory.my_signer_addresses() if self.mgr else ())
        except Exception as e:
            self.relay_status.text = f"Error: {e}"


def main():
    return SOS69069MsgApp("sos69069 msg", "org.sos69069.msg")
