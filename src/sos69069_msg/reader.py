"""Read self-posts for My and Other, merge chronologically.

On-chain each address only posts intendedTo = itself.
The app (off-chain) knows the pair and merges both streams into one chat
labeled Me / Other.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional, Set, Tuple

from .abi import SIGNATURE_RECORDED_TOPIC, decode_signature_recorded
from .config import CONTRACT_ADDRESS
from .ethcrypto import normalize_address, parse_address
from .message_engine import short_code
from .rpc import RpcClient, RpcError

OVERLAP = 20
DEFAULT_LOOKBACK = 500_000
MIN_CHUNK = 1_000
MAX_MESSAGES = 50
PAGE_SIZE = 10
_RANGE_HINTS = ("range", "limit", "exceed", "too many", "too large", "large", "max",
                "results", "10000", "query returned", "more than")


def _addr_from_topic(topic: str) -> str:
    return normalize_address("0x" + topic[-40:])


def _is_range_error(err: Exception) -> bool:
    m = str(err).lower()
    return any(h in m for h in _RANGE_HINTS)


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
    intended_to: str = ""

    def line(self, my_address: str = "") -> str:
        t = datetime.fromtimestamp(self.timestamp, timezone.utc)
        when = t.strftime("%d/%m/%Y, %H:%M:%S")
        if my_address and self.signer.lower() == my_address.lower():
            who = "Me"
        else:
            who = "Other"
        code = short_code(self.payload_hash) if self.payload_hash else "----"
        tx = self.tx_hash if str(self.tx_hash).startswith("0x") else ("0x" + str(self.tx_hash))
        reply_id = tx[2:10] if len(tx) >= 10 else code.lower()
        return (
            f"{self.text}\n"
            f"{who}\n"
            f"{self.signer}\n"
            f"tx{tx}\n"
            f"· block {self.block} · {when}\n"
            f"TRUST Received 1 SOS ·  #{code}\n"
            f"REPLY (start conv {reply_id})"
        )


def scan_intended_to(
    rpc,
    intended_to: str,
    from_block: int,
    to_block: int,
    chunk: Optional[int] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> List[Message]:
    """All SignatureRecorded where intendedTo == intended_to (self-posts preferred)."""
    d_topic = "0x" + parse_address(intended_to).rjust(32, b"\x00").hex()
    contract = normalize_address(CONTRACT_ADDRESS)
    topic0 = "0x" + SIGNATURE_RECORDED_TOPIC.hex()
    chunk = chunk or max(1, to_block - from_block + 1)
    msgs: List[Message] = []
    start = from_block
    while start <= to_block:
        end = min(start + chunk - 1, to_block)
        if progress:
            progress(f"Scanning {intended_to[:10]}… blocks {start}–{end}")
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
                    f"{e}. RPC/Etherscan range limit — set a later 'scan from block'."
                ) from e
            chunk = max(MIN_CHUNK, chunk // 2)
            continue

        for log in logs:
            try:
                raw = log.get("data", "")
                if isinstance(raw, str):
                    raw = bytes.fromhex(raw.removeprefix("0x"))
                ph_b, _sig, ts, meta = decode_signature_recorded(raw)
                # Etherscan may put timeStamp on the log
                if not ts and log.get("timeStamp"):
                    ts = int(str(log["timeStamp"]), 16) if str(log["timeStamp"]).startswith("0x") else int(log["timeStamp"])
                topics = log.get("topics", [])
                signer = _addr_from_topic(topics[1]) if len(topics) > 1 else ""
                submitter = _addr_from_topic(topics[3]) if len(topics) > 3 else ""
                # Prefer self-posts (signer == intendedTo); still keep others aimed at this addr
                msgs.append(Message(
                    block=int(log.get("blockNumber", "0x0"), 16),
                    log_index=int(log.get("logIndex", "0x0"), 16),
                    tx_hash=log.get("transactionHash", ""),
                    timestamp=ts or 0,
                    signer=signer,
                    submitter=submitter,
                    text=meta,
                    payload_hash="0x" + ph_b.hex(),
                    intended_to=intended_to,
                ))
            except Exception:
                continue
        start = end + 1
    return msgs


@dataclass
class Inbox:
    """Cache for one local pair. Cleared when conversation ends."""
    VERSION = 3
    path: str = ""
    last_block: Optional[int] = None
    messages: List[Message] = field(default_factory=list)
    outbox: List[dict] = field(default_factory=list)

    def __init__(self, path: str):
        self.path = path
        self.last_block = None
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

    def _save(self) -> None:
        with open(self.path, "w") as f:
            json.dump({
                "v": self.VERSION,
                "last_block": self.last_block,
                "messages": [asdict(m) for m in self.messages],
                "outbox": self.outbox,
            }, f)

    def clear(self) -> None:
        self.messages = []
        self.outbox = []
        self.last_block = None
        try:
            if os.path.exists(self.path):
                os.unlink(self.path)
        except OSError:
            pass

    def merge(self, new_msgs: List[Message], latest_block: int) -> int:
        existing = {(m.block, m.log_index, m.signer.lower()) for m in self.messages}
        added = 0
        for m in new_msgs:
            key = (m.block, m.log_index, m.signer.lower())
            if key not in existing:
                self.messages.append(m)
                existing.add(key)
                added += 1
        self.messages.sort(key=lambda m: (m.block, m.log_index, m.timestamp))
        if len(self.messages) > MAX_MESSAGES:
            self.messages = self.messages[-MAX_MESSAGES:]
        self.last_block = latest_block
        self._save()
        return added

    def add_pending(self, payload_hash_hex: str, text: str) -> None:
        self.outbox.append({
            "ph": payload_hash_hex,
            "text": text,
            "ts": int(time.time()),
            "tx": "",
        })
        self._save()

    def mark_submitted(self, payload_hash_hex: str, tx: str) -> None:
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

    def render(self, my_address: str = "") -> str:
        lines = []
        for o in reversed(self.pending()):
            code = short_code(o["ph"])
            lines.append(
                f"{o['text']}\n"
                f"Me\n"
                f"⏳ NOT submitted yet\n"
                f"#{code}"
            )
        for m in reversed(self.messages):
            lines.append(m.line(my_address))
        if not lines:
            return (
                "No messages yet.\n\n"
                "Each side posts to their own address.\n"
                "Sign on SEND, submit on RELAY, then CHECK."
            )
        return "\n\n────────────────────\n\n".join(lines)

    def entries(self, my_address: str = "") -> List[dict]:
        """Structured, newest-first entries for card-style rendering + pagination.
        Each entry: pending, text, who, address, tx, block, when, code, reply_id.
        """
        out: List[dict] = []
        for o in reversed(self.pending()):
            code = short_code(o["ph"])
            out.append({
                "pending": True,
                "text": o["text"],
                "who": "Me",
                "address": my_address,
                "tx": "",
                "block": None,
                "when": "",
                "code": code,
                "reply_id": code.lower(),
            })
        for m in reversed(self.messages):
            t = datetime.fromtimestamp(m.timestamp, timezone.utc)
            when = t.strftime("%d/%m/%Y, %H:%M:%S")
            who = "Me" if my_address and m.signer.lower() == my_address.lower() else "Other"
            code = short_code(m.payload_hash) if m.payload_hash else "----"
            tx = m.tx_hash if str(m.tx_hash).startswith("0x") else ("0x" + str(m.tx_hash))
            reply_id = tx[2:10] if len(tx) >= 10 else code.lower()
            out.append({
                "pending": False,
                "text": m.text,
                "who": who,
                "address": m.signer,
                "tx": tx,
                "block": m.block,
                "when": when,
                "code": code,
                "reply_id": reply_id,
            })
        return out

    def page_count(self, my_address: str = "") -> int:
        total = len(self.messages) + len(self.pending())
        return max(1, -(-total // PAGE_SIZE))  # ceil div


def sync_pair(
    rpc,
    my_address: str,
    other_address: str,
    inbox: Inbox,
    from_block: Optional[int] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> int:
    """Fetch self-posts for My and Other, merge by chronology."""
    latest = rpc.block_number()
    if from_block is not None:
        start = from_block
    elif inbox.last_block is not None:
        start = max(0, inbox.last_block + 1 - OVERLAP)
    else:
        start = max(0, latest - DEFAULT_LOOKBACK)

    a = normalize_address(my_address)
    b = normalize_address(other_address)
    msgs_a = scan_intended_to(rpc, a, start, latest, progress=progress)
    msgs_b = scan_intended_to(rpc, b, start, latest, progress=progress)
    # Keep only self-posts for a clean pair view (signer == intendedTo)
    def self_only(ms: List[Message], addr: str) -> List[Message]:
        al = addr.lower()
        return [m for m in ms if m.signer.lower() == al]

    merged = self_only(msgs_a, a) + self_only(msgs_b, b)
    return inbox.merge(merged, latest)
