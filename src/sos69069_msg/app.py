"""
SOS69069 MSG — CHECK · SEND · RELAY · SETUP

Protocol:
  Each user posts intendedTo = their own address (self-post).
  Locally the app pairs My + Other and merges both streams as one chat.
  Ending the conversation deletes the local A↔B link — clean page.
"""

import asyncio
import json
import os
import time
import traceback
from pathlib import Path

import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

from .address_factory import AddressFactory, generate_seed
from .config import CHAIN_ID, CONTRACT_ADDRESS, DEFAULT_ETHERSCAN_KEY, MAX_METADATA_LENGTH
from .conversation import Conversation, ConversationStore, random_wallet, start_pair
from .eip712 import verify_record
from .etherscan import EtherscanClient
from .logo import logo_bytes
from .message_engine import prepare_and_sign, short_code
from .reader import Inbox, sync_pair
from .relayer import parse_record, submit
from .rpc import RpcClient, RpcError
from .submission import build_record_signature_call
from .ethcrypto import KeyPair, normalize_address

APP_NAME = "SOS69069 MSG"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
DEFAULT_MAX_FEE_GWEI = 50.0

BG = "#090E0A"
FIELD = "#1A2420"
PANEL = "#141A16"
GREEN = "#05AA34"
GREY = "#2F3B35"
TAB = "#3A4540"
TAB_ACTIVE = "#05AA34"
TXT = "#FFFFFF"
MUTED = "#A8B5B0"
SIDE = 18


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


def _label(text="", muted=True, size=15, bold=False, pad=(10, SIDE, 4, SIDE), align="center", **kw):
    extra = {"font_weight": "bold"} if bold else {}
    try:
        return toga.Label(
            text,
            style=_pack(pad=pad, color=MUTED if muted else TXT, background_color=BG,
                        font_size=size, text_align=align, **extra, **kw),
        )
    except Exception:
        return toga.Label(
            text,
            style=_pack(pad=pad, color=MUTED if muted else TXT, background_color=BG,
                        font_size=size, **extra, **kw),
        )


def _title(text):
    return _label(text, muted=False, size=20, bold=True, pad=(20, SIDE, 8, SIDE))


def _input(value="", placeholder=""):
    return toga.TextInput(
        value=value, placeholder=placeholder,
        style=_pack(pad=(6, SIDE, 8, SIDE), color=TXT, background_color=FIELD,
                    font_size=16, height=54),
    )


def _panel(height=160, placeholder=""):
    return toga.MultilineTextInput(
        readonly=True, value=placeholder,
        style=_pack(pad=(8, SIDE, 8, SIDE), color=TXT, background_color=PANEL,
                    font_size=15, height=height),
    )


def _button(text, handler, primary=True):
    bg = GREEN if primary else GREY
    return toga.Button(
        text, on_press=handler,
        style=_pack(pad=(12, SIDE, 12, SIDE), color=TXT, background_color=bg,
                    font_size=17, font_weight="bold", height=56),
    )


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
            box = toga.Box(style=_pack(direction=COLUMN, margin=12))
            box.add(toga.Label("Startup crashed — share this error:"))
            box.add(toga.MultilineTextInput(value=err, readonly=True,
                                            style=_pack(flex=1, height=420)))
            self.main_window.content = box
            self.main_window.show()

    def _real_startup(self):
        self.data_dir = Path(self.paths.data)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.seed_file = self.data_dir / "seed.hex"
        self.settings_file = self.data_dir / "settings.json"
        self.pair_store = ConversationStore(self.data_dir / "pair.json")
        self.inbox_path = self.data_dir / "inbox_pair.json"
        self.conv = None
        self.inbox = Inbox(str(self.inbox_path))
        self.relayer = None
        self.last_tx_link = ""
        self._refreshing = False
        self._refresh_started = 0.0
        self.settings = self._load_settings()
        self._load_relayer_seed()
        self.conv = self.pair_store.load()

        # ---------- CHECK ----------
        self.pair_status = _label("", muted=False, size=14, bold=True)
        self.check_status = _label("", muted=False, size=15, bold=True)
        self.messages_out = _panel(400)
        self.from_in = _input(placeholder="Scan from block (optional)")
        check = _col([
            _title("CHECK"),
            _label("Merged chat: your self-posts + peer self-posts (local pair only).", size=13),
            self.pair_status,
            _button("CHECK", self.do_check),
            self.check_status,
            _label("Messages", muted=False, size=17, bold=True, pad=(16, SIDE, 6, SIDE)),
            self.messages_out,
            _button("Send", self.goto_send, primary=False),
            self.from_in,
        ])

        # ---------- SEND ----------
        self.msg_in = _input(placeholder=f"Message (≤{MAX_METADATA_LENGTH} characters)")
        self.reply_code_in = _input(placeholder="Optional short code (#A3F2)")
        self.send_status = _label("", muted=False, size=15, bold=True)
        self.signed_out = _panel(220)
        send = _col([
            _title("SEND"),
            _label("Signed as you → intendedTo = your address (self-post). Max 64 chars.", size=13),
            self.msg_in,
            _label("Optional short code of the message you answer", size=14),
            self.reply_code_in,
            _button("Sign", self.sign_message),
            self.send_status,
            _label("Signed data", muted=False, size=16, bold=True),
            self.signed_out,
            _button("Send → Relay", self.goto_relay),
        ])

        # ---------- RELAY ----------
        self.relayer_in = _input(placeholder="Address OR private key (64 hex)")
        self.relayer_note = _label("", size=13)
        self.balance_label = _label("", muted=False, size=15, bold=True)
        self.relay_in = toga.MultilineTextInput(
            placeholder="Signed record JSON",
            style=_pack(pad=(8, SIDE, 8, SIDE), color=TXT, background_color=FIELD,
                        font_size=14, height=200))
        self.relay_status = _label("", muted=False, size=15, bold=True)
        relay = _col([
            _title("RELAY"),
            _label("Paste a 64-hex PRIVATE KEY to pay gas, or leave the default relayer.", size=13),
            self.relayer_in,
            self.relayer_note,
            _button("Check balance", self.check_balance, primary=False),
            self.balance_label,
            _label("Signed record to submit", muted=False, size=15, bold=True),
            self.relay_in,
            _button("Submit to Ethereum", self.submit_record),
            self.relay_status,
            _button("Copy tx link", self._copier(lambda: self.last_tx_link, "tx link",
                                                 self.relay_status), primary=False),
        ])

        # ---------- SETUP ----------
        self.my_out = _panel(90, "My conversation wallet appears here.")
        self.other_in = _input(placeholder="Other address (0x…)")
        self.conv_out = _panel(120)
        self.copy_status = _label("", muted=False, size=14)
        self.rpc_in = _input(value=self.settings["rpc_url"])
        self.es_in = _input(value=self.settings.get("etherscan_key", DEFAULT_ETHERSCAN_KEY))
        self.cap_in = _input(value=str(self.settings["max_fee_gwei"]))
        self.net_status = _label("", muted=False, size=15, bold=True)
        setup = _col([
            _title("SETUP"),
            _label(
                "Generate your wallet, paste the other person's address, start.\n"
                "On-chain you only post to yourself. The pair is local only.",
                size=13,
            ),
            _label("1. My conversation wallet", muted=False, size=16, bold=True),
            _button("Generate my wallet", self.gen_my_wallet),
            self.my_out,
            _button("Copy my address", self._copier(
                lambda: self.conv.my_address if self.conv else "", "my address", self.copy_status),
                primary=False),
            self.copy_status,
            _label("2. Other address (from the other person)", muted=False, size=16, bold=True),
            self.other_in,
            _button("Start conversation", self.start_conversation),
            self.conv_out,
            _button("End conversation (wipe local pair)", self.end_conversation, primary=False),
            _title("Network"),
            _label("Etherscan API key (CHECK). Paste your own if needed.", size=13),
            self.es_in,
            _label("RPC URL (SEND / RELAY)", size=13),
            self.rpc_in,
            _label("Max gas fee (gwei)", size=14),
            self.cap_in,
            _button("Save network settings", self.save_network, primary=False),
            self.net_status,
        ])

        bodies = {"CHECK": check, "SEND": send, "RELAY": relay, "SETUP": setup}
        self.pages = {}
        for name, body in bodies.items():
            scroller = toga.ScrollContainer(
                content=body, horizontal=False,
                style=_pack(flex=1, background_color=BG))
            self.pages[name] = _col([self._header(name, list(bodies)), scroller], flex=1)

        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = self.pages["SETUP"] if not self.conv else self.pages["CHECK"]
        self.main_window.show()
        self._hide_title_bar()
        self._refresh_pair_ui()
        if self.relayer:
            self.relayer_in.value = self.relayer.address
            self.relayer_note.text = "Default relayer (seed-derived). Paste any private key to override."

    # ------------------------------------------------------------------ header
    def _header(self, active: str, names: list):
        def make_tab(n):
            def go(widget, **kw):
                self.main_window.content = self.pages[n]
            color = TAB_ACTIVE if n == active else TAB
            return toga.Button(
                n, on_press=go,
                style=_pack(pad=(14, 4, 14, 4), color=TXT, background_color=color,
                            font_size=16, font_weight="bold", flex=1, height=54),
            )
        try:
            logo = toga.ImageView(
                toga.Image(data=logo_bytes()),
                style=_pack(width=40, height=40, pad=(10, 8, 6, SIDE)))
        except Exception:
            logo = _label("69069", muted=False, size=18, bold=True, pad=(12, 8, 6, SIDE))
        top = _row([
            logo,
            _label(APP_NAME, muted=False, size=18, bold=True, pad=(14, 8, 6, 4), align="left"),
        ])
        tabs = _row([make_tab(n) for n in names])
        return _col([top, tabs])

    def _hide_title_bar(self):
        try:
            from java import jclass
            activity = self._impl.native
            activity.getSupportActionBar().hide()
        except Exception:
            try:
                activity.requestWindowFeature(1)
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

    # ------------------------------------------------------------------ settings / relayer seed
    def _load_settings(self):
        s = {
            "rpc_url": DEFAULT_RPC,
            "max_fee_gwei": DEFAULT_MAX_FEE_GWEI,
            "etherscan_key": DEFAULT_ETHERSCAN_KEY,
        }
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
            self.settings["rpc_url"] = self.rpc_in.value.strip()
            self.settings["max_fee_gwei"] = cap
            self.settings["etherscan_key"] = (self.es_in.value or "").strip() or DEFAULT_ETHERSCAN_KEY
            self._save_settings()
            self.net_status.text = "Saved ✔"
        except Exception as e:
            self.net_status.text = f"Error: {e}"

    def _rpc(self):
        return RpcClient(self.settings["rpc_url"])

    def _check_backends(self):
        """Etherscan first (if key set), then RPC fallback."""
        backends = []
        key = (self.settings.get("etherscan_key") or "").strip()
        if key:
            try:
                backends.append(("etherscan", EtherscanClient(key, CHAIN_ID)))
            except Exception:
                pass
        backends.append(("rpc", self._rpc()))
        return backends

    def _load_relayer_seed(self):
        """Optional seed only for a default gas-paying relayer key."""
        if not self.seed_file.exists():
            seed = generate_seed()
            self.seed_file.write_text(seed.hex())
        else:
            seed = _from_hex(self.seed_file.read_text())
        factory = AddressFactory(seed, str(self.data_dir / "signer_counter.json"))
        self.relayer = factory.relayer_key(0)

    def _refresh_pair_ui(self):
        if self.conv:
            self.my_out.value = (
                f"My address:\n{self.conv.my_address}\n\n"
                f"(private key stays on this device)"
            )
            self.other_in.value = self.conv.other_address
            self.pair_status.text = (
                f"My: {self.conv.my_address[:10]}…\n"
                f"Other: {self.conv.other_address[:10]}…"
            )
            self.conv_out.value = (
                f"Active pair (local only)\n\n"
                f"My:    {self.conv.my_address}\n"
                f"Other: {self.conv.other_address}\n\n"
                f"On-chain each posts only to themselves.\n"
                f"Contract: {CONTRACT_ADDRESS}"
            )
            self.messages_out.value = self.inbox.render(self.conv.my_address)
        else:
            self.my_out.value = "No wallet yet — tap Generate my wallet."
            self.other_in.value = ""
            self.pair_status.text = "No active conversation — open SETUP."
            self.conv_out.value = "Clean page. Generate wallet, paste Other, Start."
            self.messages_out.value = ""

    # ------------------------------------------------------------------ conversation lifecycle
    def gen_my_wallet(self, widget, **kwargs):
        try:
            other = (self.other_in.value or "").strip()
            # Generate only; Other may be filled later
            kp = random_wallet()
            if other:
                self.conv = start_pair(kp, other)
                self.pair_store.save(self.conv)
            else:
                # Temporary: hold key until Other is set
                self.conv = Conversation(kp, "0x" + "00" * 20)
                self.pair_store.clear()  # not a real pair yet
            self._refresh_pair_ui()
            self.conv_out.value = (
                f"My wallet ready:\n{kp.address}\n\n"
                f"Share this address with the other person.\n"
                f"Then paste their address below and tap Start conversation."
            )
        except Exception as e:
            self.conv_out.value = f"Error: {e}"

    def start_conversation(self, widget, **kwargs):
        try:
            other = (self.other_in.value or "").strip()
            if not other:
                raise ValueError("Paste the other person's address")
            if self.conv and self.conv.other != "0x" + "00" * 20:
                my = self.conv.my
            elif self.conv:
                my = self.conv.my
            else:
                my = random_wallet()
            self.conv = start_pair(my, other)
            self.pair_store.save(self.conv)
            self.inbox = Inbox(str(self.inbox_path))
            self._refresh_pair_ui()
            self.conv_out.value = (
                f"Conversation started (local pair only).\n\n"
                f"My:    {self.conv.my_address}\n"
                f"Other: {self.conv.other_address}\n\n"
                f"Open CHECK to load the merged timeline."
            )
            self.main_window.content = self.pages["CHECK"]
        except Exception as e:
            self.conv_out.value = f"Error: {e}"

    def end_conversation(self, widget, **kwargs):
        """Wipe local A↔B link and inbox — clean page for the next chat."""
        self.pair_store.clear()
        if self.inbox:
            self.inbox.clear()
        self.conv = None
        self.inbox = Inbox(str(self.inbox_path))
        self._refresh_pair_ui()
        self.conv_out.value = (
            "Conversation ended.\n"
            "Local pair and message cache wiped.\n"
            "Generate a new wallet to start clean."
        )
        self.check_status.text = "No active conversation"
        self.messages_out.value = ""

    # ------------------------------------------------------------------ CHECK
    async def do_check(self, widget, **kwargs):
        if not self.conv or self.conv.other == "0x" + "00" * 20:
            self.check_status.text = "Start a conversation first (SETUP)"
            return
        if self._refreshing and time.monotonic() - self._refresh_started < 90:
            self.check_status.text = "Already scanning…"
            return
        self._refreshing = True
        self._refresh_started = time.monotonic()
        self.check_status.text = "Scanning My + Other…"
        loop = asyncio.get_running_loop()

        def progress(msg):
            loop.call_soon_threadsafe(lambda: setattr(self.check_status, "text", msg))

        last_err = None
        try:
            frm = int(self.from_in.value.strip()) if self.from_in.value.strip() else None
            if frm is None:
                self.inbox.last_block = None  # full lookback on manual CHECK

            my, other = self.conv.my_address, self.conv.other_address
            for name, client in self._check_backends():
                try:
                    new = await asyncio.to_thread(
                        sync_pair, client, my, other, self.inbox, frm, progress)
                    self.messages_out.value = self.inbox.render(my)
                    total = len(self.inbox.messages) + len(self.inbox.pending())
                    if total == 0:
                        self.check_status.text = (
                            f"0 messages · via {name} · block {self.inbox.last_block}\n"
                            f"No self-posts yet for this pair."
                        )
                    else:
                        self.check_status.text = (
                            f"{new} new · {total} total · via {name} · block {self.inbox.last_block}"
                        )
                    return
                except Exception as e:
                    last_err = e
                    continue
            self.check_status.text = f"Error: {type(last_err).__name__}: {last_err}"
        except Exception as e:
            self.check_status.text = f"Error: {type(e).__name__}: {e}"
        finally:
            self._refreshing = False

    # ------------------------------------------------------------------ SEND
    def sign_message(self, widget, **kwargs):
        try:
            if not self.conv or self.conv.other == "0x" + "00" * 20:
                raise ValueError("Start a conversation first (SETUP)")
            text = (self.msg_in.value or "").strip()
            if not text:
                raise ValueError("Type a message first")
            key = self.conv.my
            ph, meta, sig = prepare_and_sign(
                key, text, reply_code=self.reply_code_in.value or "")
            # intendedTo is always My (self-post)
            if not verify_record(key.address, key.address, ph, meta, sig):
                raise RuntimeError("Local signature check failed")
            call = build_record_signature_call(
                key.address, key.address, ph, sig, meta)
            record = json.dumps({
                "to": call["to"], "chainId": CHAIN_ID, "function": call["function"],
                "signer": call["args"][0], "intendedTo": call["args"][1],
                "payloadHash": _hex(ph), "signature": _hex(sig), "metadata": meta,
            }, indent=2)
            self.signed_out.value = record
            self.relay_in.value = record
            self.inbox.add_pending(_hex(ph), meta)
            self.messages_out.value = self.inbox.render(key.address)
            code = short_code(_hex(ph))
            self.send_status.text = f"Signed ✔  #{code}  (self-post) — open RELAY and Submit"
            self.msg_in.value = ""
            self.reply_code_in.value = ""
        except Exception as e:
            self.send_status.text = f"Error: {e}"

    # ------------------------------------------------------------------ RELAY
    def _active_relayer(self) -> KeyPair:
        raw = (self.relayer_in.value or "").strip().removeprefix("0x")
        if len(raw) == 64:
            try:
                return KeyPair.from_private_key(bytes.fromhex(raw))
            except Exception as e:
                raise ValueError(f"Invalid private key: {e}") from e
        if not self.relayer:
            raise ValueError("No relayer")
        return self.relayer

    async def check_balance(self, widget, **kwargs):
        try:
            relayer = self._active_relayer()
            wei = await asyncio.to_thread(self._rpc().balance, relayer.address)
            self.balance_label.text = f"{wei / 1e18:.6f} ETH\n{relayer.address}"
        except Exception as e:
            self.balance_label.text = f"Error: {type(e).__name__}: {e}"

    async def submit_record(self, widget, **kwargs):
        try:
            relayer = self._active_relayer()
            rec = parse_record(self.relay_in.value)
            self.relay_status.text = f"Submitting with {relayer.address[:12]}…"
            rpc = self._rpc()
            cap = float(self.settings["max_fee_gwei"])
            tx = await asyncio.to_thread(submit, rpc, relayer, rec, cap)
            self.last_tx_link = f"https://etherscan.io/tx/{tx}"
            self.relay_status.text = f"Sent ✔\n{self.last_tx_link}"
            ph = rec.get("payload_hash") or rec.get("payloadHash") or ""
            if isinstance(ph, bytes):
                ph = "0x" + ph.hex()
            elif isinstance(ph, str) and ph and not ph.startswith("0x"):
                ph = "0x" + ph
            if ph:
                self.inbox.mark_submitted(ph, tx)
                if self.conv:
                    self.messages_out.value = self.inbox.render(self.conv.my_address)
        except Exception as e:
            self.relay_status.text = f"Error: {type(e).__name__}: {e}"


def main():
    return SOS69069MsgApp("sos69069 msg", "org.sos69069.msg")
