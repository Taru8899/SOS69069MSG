"""Read EVERYTHING sent to address D from SignatureRecorded logs.

All metadata is plain public text.
Message cards match sos69069.com density (body, signer, tx, block, time, TRUST, REPLY).
Pending (signed but not yet submitted) messages appear at the top.
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
from .message_engine import short_code
from .rpc import RpcClient, RpcError

OVERLAP = 20
DEFAULT_LOOKBACK = 1_000_000
MIN_CHUNK = 1_000
_RANGE_HINTS = ("range", "limit", "exceed", "too many", "too large", "large", "max",
                "results", "10000", "query returned", "more than", "smaller", "dataset", "window")


def short(addr: str) -> str:
    if not addr or len(addr) < 10:
        return addr or "?"
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
    payload_hash: str = ""

    def line(self, mine=()) -> str:
        """Dense card matching sos69069.com."""
        t = datetime.fromtimestamp(self.timestamp, timezone.utc)
        when = t.strftime("%d/%m/%Y, %H:%M:%S")
        who = "you" if self.signer in mine else self.signer
        code = short_code(self.payload_hash) if self.payload_hash else "----"
        tx = self.tx_hash if str(self.tx_hash).startswith("0x") else ("0x" + str(self.tx_hash))
        reply_id = tx[2:10] if len(tx) >= 10 else code.lower()
        return (
            f"{self.text}\n"
            f"{who}\n"
            f"tx{tx}\n"
            f"· block {self.block} · {when}\n"
            f"TRUST Received 1 SOS ·  #{code}\n"
            f"REPLY (start conv {reply_id})"
        )


_REPLY = re.compile(r"^#([0-9A-Fa-f]{4})\s+(.*)$", re.S)


def split_reply(text: str) -> Tuple[str, str]:
    """'#A3F2 hello' -> ('A3F2', 'hello'); anything else -> ('', text)."""
    m = _REPLY.match(text or "")
    return (m.group(1).upper(), m.group(2)) if m else ("", text or "")


def _fmt(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%d/%m/%Y, %H:%M:%S")


def _0x(h: str) -> str:
    h = str(h or "")
    return h if h.startswith("0x") or not h else "0x" + h


def _addr_from_topic(topic: str) -> str:
    return normalize_address("0x" + topic[-40:])


def _is_range_error(err: Exception) -> bool:
    m = str(err).lower()
    if "rate limit" in m or "api key" in m or "apikey" in m:   # not a range problem: don't shrink
        return False
    return any(h in m for h in _RANGE_HINTS)


def scan(rpc: RpcClient, d: str, from_block: int, to_block: int,
         chunk: Optional[int] = None,
         progress: Optional[Callable[[str], None]] = None) -> List[Message]:
    d_topic = "0x" + parse_address(d).rjust(32, b"\x00").hex()
    contract = normalize_address(CONTRACT_ADDRESS)
    topic0 = "0x" + SIGNATURE_RECORDED_TOPIC.hex()
    chunk = chunk or max(1, to_block - from_block + 1)
    msgs: List[Message] = []
    start = from_block
    while start <= to_block:
        end = min(start + chunk - 1, to_block)
        if progress:
            progress(f"Scanning blocks {start}–{end}…")
        try:
            logs = rpc.get_logs({
                "address": contract,
                "fromBlock": hex(start),
                "toBlock": hex(end),
                "topics": [topic0, None, d_topic],
            })
        except RpcError as e:
            if not _is_range_error(e):
                raise
            if chunk <= MIN_CHUNK:
                raise RpcError(
                    f"{e}. This RPC limits log queries; try another RPC URL "
                    "or enter a later 'scan from block'."
                ) from e
            chunk = max(MIN_CHUNK, chunk // 2)
            continue

        for log in logs:
            try:
                raw = log.get("data", "")
                if isinstance(raw, str):
                    raw = bytes.fromhex(raw.removeprefix("0x"))
                ph_b, _sig, ts, meta = decode_signature_recorded(raw)
                topics = log.get("topics", [])
                signer = _addr_from_topic(topics[1]) if len(topics) > 1 else ""
                submitter = _addr_from_topic(topics[3]) if len(topics) > 3 else ""
                msgs.append(Message(
                    block=int(log.get("blockNumber", "0x0"), 16),
                    log_index=int(log.get("logIndex", "0x0"), 16),
                    tx_hash=log.get("transactionHash", ""),
                    timestamp=ts,
                    signer=signer,
                    submitter=submitter,
                    text=meta,
                    payload_hash="0x" + ph_b.hex(),
                ))
            except Exception:
                continue
        start = end + 1
    return msgs


@dataclass
class Inbox:
    VERSION = 2
    path: str = ""
    last_block: Optional[int] = None
    last_scan_from: Optional[int] = None
    messages: List[Message] = field(default_factory=list)
    outbox: List[dict] = field(default_factory=list)

    def __init__(self, path: str):
        self.path = path
        self.last_block = None
        self.last_scan_from = None
        self.messages = []
        self.outbox = []
        if os.path.exists(path):
            try:
                with open(path) as f:
                    j = json.load(f)
                self.last_block = j.get("last_block")
                self.outbox = j.get("outbox", [])
                for m in j.get("messages", []):
                    self.messages.append(Message(**m))
            except Exception:
                pass

    def _save(self):
        with open(self.path, "w") as f:
            json.dump({
                "v": self.VERSION,
                "last_block": self.last_block,
                "messages": [asdict(m) for m in self.messages],
                "outbox": self.outbox,
            }, f)

    def merge(self, new_msgs: List[Message], latest_block: int) -> int:
        existing = {(m.block, m.log_index) for m in self.messages}
        added = 0
        for m in new_msgs:
            key = (m.block, m.log_index)
            if key not in existing:
                self.messages.append(m)
                existing.add(key)
                added += 1
        self.messages.sort(key=lambda m: (m.block, m.log_index))
        self.last_block = latest_block
        self._save()
        return added

    def add_pending(self, payload_hash_hex: str, text: str):
        self.outbox.append({
            "ph": payload_hash_hex,
            "text": text,
            "ts": int(time.time()),
            "tx": "",
        })
        self._save()

    def mark_submitted(self, payload_hash_hex: str, tx: str):
        ph = payload_hash_hex if str(payload_hash_hex).startswith("0x") else ("0x" + str(payload_hash_hex))
        for o in self.outbox:
            op = o["ph"] if str(o["ph"]).startswith("0x") else ("0x" + str(o["ph"]))
            if op.lower() == ph.lower():
                o["tx"] = tx
        self._save()

    def pending(self) -> List[dict]:
        on_chain = {m.payload_hash.lower() for m in self.messages}
        out = []
        for o in self.outbox:
            op = o["ph"] if str(o["ph"]).startswith("0x") else ("0x" + str(o["ph"]))
            if op.lower() not in on_chain and not o.get("tx"):
                out.append(o)
        return out

    def waiting(self) -> List[dict]:
        """My signed messages that are not on chain yet (not submitted, or submitted and unmined)."""
        on_chain = {m.payload_hash.lower() for m in self.messages}
        return [o for o in self.outbox if _0x(o["ph"]).lower() not in on_chain]

    def entries(self, mine=()) -> List[dict]:
        """Everything for the CHECK list, newest first (waiting messages on top).

        Each entry: pending, status, text, reply_to, who, tx, block, when, code
        """
        out: List[dict] = []
        for o in reversed(self.waiting()):
            reply_to, body = split_reply(o["text"])
            out.append({"pending": True,
                        "status": ("⏳ Submitted, waiting to be mined" if o.get("tx")
                                   else "⏳ NOT submitted yet (open RELAY)"),
                        "text": body, "reply_to": reply_to, "who": "you",
                        "tx": _0x(o.get("tx", "")), "block": None, "when": _fmt(o["ts"]),
                        "code": short_code(o["ph"])})
        for m in reversed(self.messages):
            reply_to, body = split_reply(m.text)
            out.append({"pending": False, "status": "", "text": body, "reply_to": reply_to,
                        "who": "you" if m.signer in mine else m.signer,
                        "tx": _0x(m.tx_hash), "block": m.block, "when": _fmt(m.timestamp),
                        "code": short_code(m.payload_hash) if m.payload_hash else "----"})
        return out

    def render(self, d: str = "", mine=()) -> str:
        lines = []
        for o in reversed(self.pending()):
            code = short_code(o["ph"])
            lines.append(
                f"{o['text']}\n"
                f"⏳ NOT submitted yet\n"
                f"#{code}\n"
                f"REPLY (start conv {code.lower()})"
            )
        for m in reversed(self.messages):
            lines.append(m.line(mine))
        if not lines:
            return (
                f"No messages to {d or 'D'} yet.\n\n"
                f"Sign on SEND, then submit on RELAY."
            )
        return "\n\n────────────────────\n\n".join(lines)


def sync(rpc: RpcClient, d: str, inbox: Inbox, from_block: Optional[int] = None,
         progress: Optional[Callable[[str], None]] = None) -> int:
    latest = rpc.block_number()
    if from_block is not None:
        start = from_block
    elif inbox.last_block is not None:
        start = max(0, inbox.last_block + 1 - OVERLAP)
    else:
        start = max(0, latest - DEFAULT_LOOKBACK)
    msgs = scan(rpc, d, start, latest, progress=progress)
    inbox.last_scan_from = start
    return inbox.merge(msgs, latest)
