"""Read EVERYTHING sent to your rendezvous address D from SignatureRecorded logs.

Every record whose intendedTo == D is shown:
  decrypted   readable with this conversation's secret
  plain       unencrypted text (Encrypt switch off)
  encrypted   looks encrypted but cannot be read with this secret (someone else's, or spam)
Your own signed-but-not-yet-submitted messages are listed as pending until they appear on chain.
"""

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

from .abi import SIGNATURE_RECORDED_TOPIC, decode_signature_recorded
from .config import CONTRACT_ADDRESS
from .ethcrypto import normalize_address, parse_address
from .message_engine import read_record
from .rpc import RpcClient, RpcError

OVERLAP = 20                 # re-scan the last blocks each time: public RPCs can lag / reorg
DEFAULT_LOOKBACK = 1_000_000  # ~5 months on mainnet, first scan only (from_block overrides)
MIN_CHUNK = 1_000
_RANGE_HINTS = ("range", "limit", "exceed", "too many", "too large", "large", "max", "results",
                "10000", "query returned", "more than")
_B64 = re.compile(r"^[A-Za-z0-9_-]{22,64}$")


def short(addr: str) -> str:
    return f"{addr[:6]}…{addr[-4:]}"


@dataclass
class Message:
    block: int
    log_index: int
    tx_hash: str
    timestamp: int
    signer: str
    submitter: str
    text: str
    kind: str = "decrypted"      # decrypted | plain | encrypted
    payload_hash: str = ""

    def line(self, mine=()) -> str:
        t = datetime.fromtimestamp(self.timestamp, timezone.utc).strftime("%d %b %Y %H:%M UTC")
        who = "you" if self.signer in mine else short(self.signer)
        if self.kind == "encrypted":
            body = "🔒 encrypted, can't be read with this secret"
        elif self.kind == "plain":
            body = f"{self.text}  (unencrypted)"
        else:
            body = self.text
        return f"[{t}] from {who} → D\n{body}"


def _addr_from_topic(topic: str) -> str:
    return normalize_address("0x" + topic[-40:])


def _classify(metadata: str) -> str:
    return "encrypted" if _B64.match(metadata) else "plain"


def _is_range_error(err: Exception) -> bool:
    m = str(err).lower()
    return any(h in m for h in _RANGE_HINTS)


def scan(rpc: RpcClient, d: str, secret: bytes, from_block: int, to_block: int,
         chunk: Optional[int] = None,
         progress: Optional[Callable[[str], None]] = None) -> Tuple[List[Message], int]:
    """Returns (all messages sent to D, number that are unreadable/encrypted).

    Starts with the whole range in ONE request and halves the window only when the
    provider complains about range/result limits.
    """
    d_topic = "0x" + parse_address(d).rjust(32, b"\x00").hex()
    contract = normalize_address(CONTRACT_ADDRESS)
    topic0 = "0x" + SIGNATURE_RECORDED_TOPIC.hex()
    chunk = chunk or max(1, to_block - from_block + 1)
    msgs: List[Message] = []
    unreadable = 0
    start = from_block
    while start <= to_block:
        end = min(start + chunk - 1, to_block)
        try:
            logs = rpc.get_logs({"address": contract, "fromBlock": hex(start), "toBlock": hex(end),
                                 "topics": [topic0, None, d_topic]})
        except RpcError as e:
            if not _is_range_error(e):
                raise
            if chunk <= MIN_CHUNK:
                raise RpcError(f"{e}. This RPC limits log queries; use another RPC URL "
                               "(Setup, step 4) or enter a later 'scan from block'.") from e
            chunk = max(MIN_CHUNK, chunk // 2)
            continue
        for lg in logs:
            try:
                ph, _sig, ts, meta = decode_signature_recorded(bytes.fromhex(lg["data"][2:]))
            except Exception:
                continue  # malformed log data: cannot be shown at all
            try:
                text, kind = read_record(meta, ph, secret), "decrypted"
            except Exception:
                kind = _classify(meta)
                text = "" if kind == "encrypted" else meta
                unreadable += kind == "encrypted"
            msgs.append(Message(int(lg["blockNumber"], 16), int(lg["logIndex"], 16),
                                lg["transactionHash"], ts,
                                _addr_from_topic(lg["topics"][1]),
                                _addr_from_topic(lg["topics"][3]), text, kind, "0x" + ph.hex()))
        if progress:
            progress(f"Scanned blocks {from_block:,}–{end:,}")
        start = end + 1
    msgs.sort(key=lambda m: (m.block, m.log_index))
    return msgs, unreadable


class Inbox:
    """On-disk cache: chain messages + my pending (signed, not yet on chain) messages."""
    VERSION = 2

    def __init__(self, path: str):
        self.path = path
        self.last_block: Optional[int] = None
        self.last_scan_from: Optional[int] = None
        self.messages: List[Message] = []
        self.outbox: List[dict] = []      # {"ph","text","ts","tx"}
        if os.path.exists(path):
            try:
                with open(path) as f:
                    j = json.load(f)
                self.outbox = j.get("outbox", [])
                if j.get("v") == self.VERSION:   # older caches dropped messages: rescan from scratch
                    self.last_block = j.get("last_block")
                    self.messages = [Message(**m) for m in j.get("messages", [])]
            except Exception:
                pass

    def _save(self):
        with open(self.path, "w") as f:
            json.dump({"v": self.VERSION, "last_block": self.last_block,
                       "messages": [asdict(m) for m in self.messages], "outbox": self.outbox}, f)

    def merge(self, new: List[Message], last_block: int) -> int:
        seen = {(m.tx_hash, m.log_index) for m in self.messages}
        added = [m for m in new if (m.tx_hash, m.log_index) not in seen]
        self.messages += added
        self.messages.sort(key=lambda m: (m.block, m.log_index))
        self.last_block = last_block
        self._save()
        return len(added)

    # ---- my pending messages ----
    def add_pending(self, payload_hash_hex: str, text: str):
        self.outbox.append({"ph": payload_hash_hex, "text": text, "ts": int(time.time()), "tx": ""})
        self._save()

    def mark_submitted(self, payload_hash_hex: str, tx: str):
        for o in self.outbox:
            if o["ph"] == payload_hash_hex:
                o["tx"] = tx
        self._save()

    def pending(self) -> List[dict]:
        on_chain = {m.payload_hash for m in self.messages}
        return [o for o in self.outbox if o["ph"] not in on_chain]

    def render(self, d: Optional[str] = None, mine=(), limit: int = 30) -> str:
        """Everything sent to D, newest first (pending ones on top)."""
        parts = []
        for o in reversed(self.pending()):
            t = datetime.fromtimestamp(o["ts"], timezone.utc).strftime("%d %b %H:%M UTC")
            state = "submitted, waiting to be mined" if o["tx"] else "NOT submitted yet (Relay tab)"
            parts.append(f"⏳ [{t}] you → D\n{o['text']}\n({state})")
        if self.messages:
            shown = self.messages[-limit:][::-1]
            head = (f"Latest {len(shown)} of {len(self.messages)} message(s) to D "
                    f"{short(d) if d else ''} — newest first")
            parts += [head] if not parts else ["— on chain —\n" + head]
            parts += [m.line(mine) for m in shown]
        return "\n\n".join(parts) if parts else "(no messages yet)"


def sync(rpc: RpcClient, d: str, secret: bytes, inbox: Inbox, from_block: Optional[int] = None,
         lookback: int = DEFAULT_LOOKBACK, progress=None) -> Tuple[int, int]:
    """Fetch records to D since the last scan. Returns (new_messages, unreadable_encrypted)."""
    latest = rpc.block_number()
    if from_block is not None:
        start = from_block
    elif inbox.last_block is not None:
        start = max(0, inbox.last_block + 1 - OVERLAP)
    else:
        start = max(0, latest - lookback)
    msgs, unreadable = scan(rpc, d, secret, start, latest, progress=progress)
    inbox.last_scan_from = start
    return inbox.merge(msgs, latest), unreadable
