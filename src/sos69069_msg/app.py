"""
SOS69069 MSG — native (Toga) UI, styled like the SOS 69069 cSOS app.
Android via Briefcase; desktop via `briefcase dev`.

Pages: Setup · Send · Inbox · Relay   (pinned header: logo + title + tabs)
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
from .config import CHAIN_ID, CONTRACT_ADDRESS
from .conversation import ConversationManager
from .crypto_utils import MAX_PLAINTEXT_BYTES
from .eip712 import verify_record
from .logo import logo_bytes
from .message_engine import prepare_and_sign
from .reader import Inbox, sync
from .relayer import parse_record, submit
from .rpc import RpcClient
from .submission import build_record_signature_call

APP_NAME = "SOS69069 MSG"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"   # any mainnet https RPC works
DEFAULT_MAX_FEE_GWEI = 50.0

# ---- cSOS look ----
BG = "#090E0A"        # page
FIELD = "#242F27"     # inputs
PANEL = "#141A16"     # result boxes
GREEN = "#05AA34"     # primary buttons
GREY = "#2F3B35"      # secondary buttons
TAB = "#575757"       # tab buttons
TAB_LINE = "#4FA3D1"  # active tab underline
TXT = "#FFFFFF"
MUTED = "#C9D1CD"


def _pack(pad=None, **kw):
    """Pack with a padding shorthand (top, right, bottom, left); Toga 0.5 calls it margin."""
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


def _button(text, on_press, primary=True):
    return toga.Button(text, on_press=on_press,
                       style=_pack(pad=(8, 16, 8, 16), color=TXT, font_weight="bold", font_size=16,
                                   background_color=GREEN if primary else GREY, height=52))


def _panel(height, placeholder="", readonly=False):
    # readonly=False on purpose: Android does not allow selecting/copying text in read-only boxes
    return toga.MultilineTextInput(readonly=readonly, placeholder=placeholder,
                                   style=_pack(pad=(6, 16, 6, 16), color=TXT, background_color=PANEL,
                                               font_size=14, height=height))


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
        box = _col([
            _label(f"{APP_NAME} failed to start. Screenshot this and send it:", muted=False),
            toga.MultilineTextInput(readonly=True, value=text,
                                    style=_pack(flex=1, color=TXT, background_color=PANEL)),
        ], flex=1)
        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = box
        self.main_window.show()

    def _build(self):
        self.data_dir = Path(self.paths.data)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.seed_file = self.data_dir / "seed.hex"
        self.settings_file = self.data_dir / "settings.json"
        self.mgr = self.conv = self.secret = self.inbox = self.relayer = None
        self.last_tx_link = ""
        self._refreshing = False
        self._refresh_started = 0.0
        self._last_auto = 0.0
        self.settings = self._load_settings()
        self._load_seed()

        # ---------------- Setup ----------------
        self.seed_status = _label("", muted=False)
        self.seed_out = _panel(80, "Seed appears here once. Back it up.")
        self.seed_in = _input(placeholder="Paste 64-hex seed to import")
        self.secret_in = _input(placeholder="Shared secret (64 hex)")
        self.conv_out = _panel(150)
        self.rpc_in = _input(value=self.settings["rpc_url"])
        self.cap_in = _input(value=str(self.settings["max_fee_gwei"]))
        self.net_status = _label("", muted=False)
        self.copy_status = _label("", muted=False)
        self.keep_relayer_sw = toga.Switch(
            "Keep relayer from previous conversation", value=bool(self.settings.get("keep_relayer")),
            on_change=self.on_keep_relayer,
            style=_pack(pad=(6, 16, 2, 16), color=TXT, background_color=BG))

        setup = _col([
            _title("1. Identity"),
            self.seed_status,
            _button("Create new identity", self.create_identity),
            self.seed_out,
            _button("Copy seed", self._copier(lambda: self.seed_out.value or (
                self.seed_file.read_text() if self.seed_file.exists() else ""), "seed", self.copy_status),
                primary=False),
            self.copy_status,
            self.seed_in,
            _button("Import seed", self.import_seed, primary=False),
            _title("2. Shared secret"),
            _label("Share this secret with the person you want to chat with (in person or a private "
                   "channel). You both enter the SAME secret. Anyone who has it can read and write "
                   "to the chat, so use a new one per conversation."),
            self.secret_in,
            _button("Generate new secret", self.gen_secret, primary=False),
            _button("Copy secret", self._copier(lambda: self.secret_in.value, "secret", self.copy_status),
                    primary=False),
            _title("3. Conversation"),
            self.keep_relayer_sw,
            _label("Off: every NEW conversation gets a fresh relayer address (better privacy, "
                   "you fund it again). On: reuse the relayer you already funded."),
            _button("Start conversation", self.start_conversation),
            self.conv_out,
            _button("Copy D address", self._copier(lambda: self.conv.rendezvous_d, "D address",
                                                   self.copy_status), primary=False),
            _title("4. Network (Ethereum mainnet)"),
            _label("RPC URL (https). The provider sees your IP and queries."),
            self.rpc_in,
            _label("Max gas fee you'll pay (gwei)"),
            self.cap_in,
            _button("Save network settings", self.save_network, primary=False),
            self.net_status,
        ])

        # ---------------- Send ----------------
        self.msg_in = _input(placeholder=f"Message (≤{MAX_PLAINTEXT_BYTES} bytes encrypted)")
        self.encrypt_sw = toga.Switch("Encrypt", value=True,
                                      style=_pack(pad=(6, 16, 6, 16), color=TXT, background_color=BG))
        self.send_status = _label("", muted=False)
        self.send_out = _panel(300)
        send = _col([
            _label("Message"),
            self.msg_in,
            self.encrypt_sw,
            _button("Sign message", self.sign_message),
            self.send_status,
            _label("Signed record. Share it with anyone who can submit it, or submit it "
                   "yourself on the Relay page:"),
            self.send_out,
            _button("Copy signed record", self._copier(lambda: self.send_out.value, "signed record",
                                                       self.send_status)),
        ])

        # ---------------- Inbox ----------------
        self.from_in = _input(placeholder="Scan from block (optional)")
        self.inbox_status = _label("", muted=False)
        self.inbox_out = _panel(420)
        inbox = _col([
            _button("Refresh from chain", self.refresh_inbox),
            self.from_in,
            self.inbox_status,
            self.inbox_out,
            _button("Copy messages", self._copier(lambda: self.inbox_out.value, "messages",
                                                  self.inbox_status), primary=False),
        ])

        # ---------------- Relay ----------------
        self.relayer_in = _input()
        self.relayer_note = _label("", size=13)
        self.balance_label = _label("", muted=False)
        self.relay_in = toga.MultilineTextInput(
            placeholder="Paste a signed record JSON here",
            style=_pack(pad=(6, 16, 6, 16), color=TXT, background_color=FIELD, font_size=14, height=220))
        self.relay_status = _label("", muted=False)
        relay = _col([
            _label("Your relayer address. Send it a little ETH; it pays gas:"),
            self.relayer_in,
            self.relayer_note,
            _button("Copy relayer address", self._copier(lambda: self.relayer_in.value,
                                                         "relayer address", self.balance_label),
                    primary=False),
            _button("Check balance", self.check_balance, primary=False),
            self.balance_label,
            _label("Record to submit (yours, or a stranger's):"),
            self.relay_in,
            _button("Submit to Ethereum", self.submit_record),
            self.relay_status,
            _button("Copy tx link", self._copier(lambda: self.last_tx_link, "tx link", self.relay_status),
                    primary=False),
        ])

        # Pinned header (logo + title, tabs under it) above a scrolling body. Each page is its
        # own root Box with its own header; switching pages swaps main_window.content.
        bodies = {"Setup": setup, "Send": send, "Inbox": inbox, "Relay": relay}
        self.pages = {}
        for name, body in bodies.items():
            scroller = toga.ScrollContainer(content=body, horizontal=False,
                                            style=_pack(flex=1, background_color=BG))
            self.pages[name] = _col([self._header(name, list(bodies)), scroller], flex=1)
        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = self.pages["Setup"]
        self.main_window.show()
        self._hide_title_bar()
        self._refresh_seed_status()

    # ------------------------------------------------------------ clipboard
    def _copy(self, text: str) -> bool:
        """Copy to the system clipboard. Toga's clipboard first, native Android as fallback."""
        try:
            self.clipboard.set_text(text)
            return True
        except Exception:
            pass
        try:
            from java import jclass  # Chaquopy (Android only)
            Context = jclass("android.content.Context")
            ClipData = jclass("android.content.ClipData")
            cm = self._impl.native.getSystemService(Context.CLIPBOARD_SERVICE)
            cm.setPrimaryClip(ClipData.newPlainText("sos69069", text))
            return True
        except Exception:
            return False

    def _copier(self, getter, what: str, status):
        def handler(widget, **kwargs):
            try:
                text = getter() or ""
            except Exception:
                text = ""
            if not text.strip():
                status.text = f"Nothing to copy yet ({what})"
            elif self._copy(text):
                status.text = f"Copied {what} ✔"
            else:
                status.text = "Copy failed. Long-press the text to select it instead."
        return handler

    def _hide_title_bar(self):
        """Remove Android's title bar (the app-name block above the logo + tabs)."""
        try:
            activity = self._impl.native
            for getter in ("getSupportActionBar", "getActionBar"):
                bar = getattr(activity, getter)()
                if bar is not None:
                    bar.hide()
                    return
        except Exception:
            pass

    def _header(self, current: str, names):
        try:
            logo = toga.ImageView(toga.Image(data=logo_bytes()),
                                  style=_pack(pad=(14, 12, 10, 16), width=60, height=60,
                                              background_color=BG))
        except Exception:
            logo = _label("SOS", muted=False, size=20, bold=True)
        top = _row([logo, _label(APP_NAME, muted=False, size=24, bold=True, pad=(24, 8, 8, 4))])
        tabs = _row([
            _col([
                toga.Button(n, on_press=self._go(n),
                            style=_pack(color=TXT, background_color=TAB, font_size=16, height=54)),
                toga.Box(style=_pack(background_color=TAB_LINE if n == current else TAB, height=3)),
            ], flex=1, pad=(0, 1, 0, 1))
            for n in names
        ])
        return _col([top, tabs])

    def _go(self, name):
        async def handler(widget, **kwargs):
            self.main_window.content = self.pages[name]
            self._hide_title_bar()
            if name == "Inbox" and self.conv and time.monotonic() - self._last_auto > 15:
                await self.refresh_inbox(None, auto=True)   # latest messages to D, automatically
        return handler

    # ------------------------------------------------------------ settings
    def _load_settings(self):
        s = {"rpc_url": DEFAULT_RPC, "max_fee_gwei": DEFAULT_MAX_FEE_GWEI, "keep_relayer": False}
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
            RpcClient(self.rpc_in.value)  # validates https
            cap = float(self.cap_in.value)
            if cap <= 0:
                raise ValueError("cap must be > 0")
            self.settings.update({"rpc_url": self.rpc_in.value.strip(), "max_fee_gwei": cap})
            self._save_settings()
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
        if save:  # a brand-new identity: old relayer choices refer to the old seed
            for k in ("relayer_for", "relayer_index", "next_relayer"):
                self.settings.pop(k, None)
            self._save_settings()
        self.relayer = factory.relayer_key(self.settings.get("relayer_index", 0))
        self.conv = self.inbox = None

    def _refresh_seed_status(self):
        self.seed_status.text = "Identity loaded ✔" if self.mgr else "No identity yet"
        self.relayer_in.value = self.relayer.address if self.relayer else ""

    def create_identity(self, widget, **kwargs):
        seed = generate_seed()
        self._set_seed(seed)
        self.seed_out.value = seed.hex()
        self._refresh_seed_status()
        self.seed_status.text = ("Identity created ✔ Back up the seed below. "
                                 "Next: step 2, then 'Start conversation'.")

    def import_seed(self, widget, **kwargs):
        try:
            self._set_seed(_from_hex(self.seed_in.value))
            self.seed_in.value = ""
        except Exception as e:
            self.seed_status.text = f"Error: {e}"
            return
        self._refresh_seed_status()

    # ------------------------------------------------------------ relayer
    def on_keep_relayer(self, widget, **kwargs):
        self.settings["keep_relayer"] = bool(self.keep_relayer_sw.value)
        try:
            self._save_settings()
        except Exception:
            pass

    def _select_relayer(self, conv):
        """Pick the relayer for this conversation: remembered one, kept one, or a fresh one."""
        cid = conv.conversation_id.hex()
        mapping = self.settings.setdefault("relayer_for", {})
        if cid in mapping:
            idx, note = mapping[cid], "Same relayer as before for this conversation."
        elif not mapping:
            idx, note = 0, "Your first relayer."
        elif self.keep_relayer_sw.value:
            idx = self.settings.get("relayer_index", 0)
            note = "Kept from your previous conversation."
        else:
            idx = self.settings.get("next_relayer", 1)
            self.settings["next_relayer"] = idx + 1
            note = "Fresh relayer for this new conversation. Fund it to submit."
        mapping[cid] = idx
        self.settings["relayer_index"] = idx
        self._save_settings()
        self.relayer = self.mgr.factory.relayer_key(idx)
        self.relayer_in.value = self.relayer.address
        self.relayer_note.text = f"Relayer #{idx}. {note}"

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
            self._select_relayer(self.conv)
            self.inbox_out.value = self._render_inbox()
            self.conv_out.value = (
                f"Rendezvous D:\n{self.conv.rendezvous_d}\n\n"
                f"Chain: Ethereum mainnet ({CHAIN_ID})\nContract: {CONTRACT_ADDRESS}\n\n"
                "Conversation ready ✔ Open the Send tab.\n"
                f"{self.relayer_note.text}"
            )
            self._kick_refresh()
        except Exception as e:
            self.conv_out.value = f"Error: {e}"

    # ---------------------------------------------------------------- send
    def sign_message(self, widget, **kwargs):
        try:
            if not self.conv:
                raise ValueError("Start a conversation first (Setup tab, step 3)")
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
            self.relay_in.value = record          # ready to submit on the Relay page
            if self.inbox:
                self.inbox.add_pending(_hex(ph), self.msg_in.value)
                self.inbox_out.value = self._render_inbox()
            self.send_status.text = (f"Signed ✔ (one-time signer {key.address[:10]}…). NOT on chain yet: "
                                     "open Relay and tap Submit (the relayer needs a little ETH).")
            self.msg_in.value = ""
        except Exception as e:
            self.send_status.text = f"Error: {e}"

    # --------------------------------------------------------------- inbox
    def _render_inbox(self) -> str:
        if not self.inbox or not self.conv:
            return ""
        mine = self.mgr.factory.my_signer_addresses() if self.mgr else ()
        return self.inbox.render(self.conv.rendezvous_d, mine)

    def _kick_refresh(self):
        """Fire-and-forget background refresh (no-op if there is no running event loop)."""
        try:
            asyncio.get_running_loop().create_task(self.refresh_inbox(None, auto=True))
        except RuntimeError:
            pass

    def _set_inbox_status(self, text: str):
        self.inbox_status.text = text

    async def refresh_inbox(self, widget, auto=False, **kwargs):
        if not self.conv or not self.inbox:
            self.inbox_status.text = "Start a conversation first (Setup tab, step 3)"
            return
        if self._refreshing and time.monotonic() - self._refresh_started < 90:
            self.inbox_status.text = "Already scanning… please wait a moment."
            return
        self._refreshing, self._refresh_started = True, time.monotonic()
        self.inbox_status.text = "Checking for new messages…" if auto else "Scanning the chain…"
        loop = asyncio.get_running_loop()

        def progress(msg):  # called from the worker thread
            loop.call_soon_threadsafe(self._set_inbox_status, msg)

        try:
            frm = int(self.from_in.value) if self.from_in.value.strip() else None
            rpc, conv, inbox, secret = self._rpc(), self.conv, self.inbox, self.secret
            new, unreadable = await asyncio.to_thread(
                sync, rpc, conv.rendezvous_d, secret, inbox, frm, progress=progress)
            self.inbox_out.value = self._render_inbox()
            self._last_auto = time.monotonic()
            n = len(inbox.messages)
            where = f"blocks {inbox.last_scan_from:,}–{inbox.last_block:,}"
            if n == 0:
                msg = f"No records to this D on chain yet ({where})."
                pend = len(inbox.pending())
                if pend:
                    msg += (f" You have {pend} signed message(s) that are not on chain: "
                            "submit them on the Relay tab (the relayer needs a little ETH).")
                else:
                    msg += (" Either nothing was submitted to this D, or the other person "
                            "used a different shared secret (then their D differs).")
            else:
                msg = (f"{n} message(s) to D on chain ({new} new"
                       f"{f', {unreadable} encrypted with another secret' if unreadable else ''}). "
                       f"Scanned {where}.")
            self.inbox_status.text = msg
        except Exception as e:
            self.inbox_status.text = f"Error: {e}"
        finally:
            self._refreshing = False

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
            self.last_tx_link = f"https://etherscan.io/tx/{tx}"
            if self.inbox:
                self.inbox.mark_submitted(_hex(rec["payload_hash"]), tx)
                self.inbox_out.value = self._render_inbox()
            self.relay_status.text = (f"Sent ✔ Mining takes ~15–60 s, then open Inbox → Refresh.\n"
                                      f"{self.last_tx_link}")
        except Exception as e:
            self.relay_status.text = f"Error: {e}"


def main():
    return SOS69069MsgApp(APP_NAME, "org.sos69069.msg")
