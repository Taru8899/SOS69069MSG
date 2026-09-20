"""Read your conversation from SignatureRecorded logs and decrypt it."""

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

from .abi import SIGNATURE_RECORDED_TOPIC, decode_signature_recorded
from .config import CONTRACT_ADDRESS
from .ethcrypto import normalize_address, parse_address
from .message_engine import read_record
from .rpc import RpcClient, RpcError


@dataclass
class Message:
    block: int
    log_index: int
    tx_hash: str
    timestamp: int
    signer: str
    submitter: str
    text: str

    def line(self, mine=()) -> str:
        t = datetime.fromtimestamp(self.timestamp, timezone.utc).strftime("%d %b %Y %H:%M UTC")
        who = "you" if self.signer in mine else short(self.signer)
        return f"[{t}] from {who} → D\n{self.text}"


def short(addr: str) -> str:
    return f"{addr[:6]}…{addr[-4:]}"


def _addr_from_topic(topic: str) -> str:
    return normalize_address("0x" + topic[-40:])


def scan(rpc: RpcClient, d: str, secret: bytes, from_block: int, to_block: int,
         chunk: int = 5000,
         progress: Optional[Callable[[str], None]] = None) -> Tuple[List[Message], int]:
    """Returns (decrypted messages, number of records on D that were not ours)."""
    d_topic = "0x" + parse_address(d).rjust(32, b"\x00").hex()
    msgs: List[Message] = []
    noise = 0
    start = from_block
    while start <= to_block:
        end = min(start + chunk - 1, to_block)
        try:
            logs = rpc.get_logs({
                "address": normalize_address(CONTRACT_ADDRESS),
                "fromBlock": hex(start), "toBlock": hex(end),
                "topics": ["0x" + SIGNATURE_RECORDED_TOPIC.hex(), None, d_topic],
            })
        except RpcError:
            if chunk > 500:            # provider limits: retry with smaller windows
                chunk //= 2
                continue
            raise
        for lg in logs:
            try:
                ph, _sig, ts, meta = decode_signature_recorded(bytes.fromhex(lg["data"][2:]))
                text = read_record(meta, ph, secret)
            except Exception:
                noise += 1
                continue
            msgs.append(Message(int(lg["blockNumber"], 16), int(lg["logIndex"], 16),
                                lg["transactionHash"], ts,
                                _addr_from_topic(lg["topics"][1]),
                                _addr_from_topic(lg["topics"][3]), text))
        if progress:
            progress(f"scanned to block {end}")
        start = end + 1
    msgs.sort(key=lambda m: (m.block, m.log_index))
    return msgs, noise


class Inbox:
    """On-disk cache so re-scans only fetch new blocks."""

    def __init__(self, path: str):
        self.path = path
        self.last_block: Optional[int] = None
        self.messages: List[Message] = []
        if os.path.exists(path):
            with open(path) as f:
                j = json.load(f)
            self.last_block = j.get("last_block")
            self.messages = [Message(**m) for m in j.get("messages", [])]

    def merge(self, new: List[Message], last_block: int):
        seen = {(m.tx_hash, m.log_index) for m in self.messages}
        self.messages += [m for m in new if (m.tx_hash, m.log_index) not in seen]
        self.messages.sort(key=lambda m: (m.block, m.log_index))
        self.last_block = last_block
        with open(self.path, "w") as f:
            json.dump({"last_block": last_block, "messages": [asdict(m) for m in self.messages]}, f)

    def render(self, d: Optional[str] = None, mine=(), limit: int = 30) -> str:
        """Latest messages sent to D (intendedTo == D), newest first."""
        if not self.messages:
            return "(no messages yet)"
        shown = self.messages[-limit:][::-1]
        head = (f"Latest {len(shown)} of {len(self.messages)} message(s) to D "
                f"{short(d) if d else ''} — newest first\n\n")
        return head + "\n\n".join(m.line(mine) for m in shown)


def sync(rpc: RpcClient, d: str, secret: bytes, inbox: Inbox, from_block: Optional[int] = None,
         lookback: int = 50_000, progress=None) -> Tuple[int, int]:
    """Fetch new records since last scan. Returns (new_messages, noise)."""
    latest = rpc.block_number()
    start = from_block if from_block is not None else (
        inbox.last_block + 1 if inbox.last_block is not None else max(0, latest - lookback))
    before = len(inbox.messages)
    msgs, noise = scan(rpc, d, secret, start, latest, progress=progress)
    inbox.merge(msgs, latest)
    return len(inbox.messages) - before, noise
