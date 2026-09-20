"""Tiny JSON-RPC client over the standard library (no web3 needed; works on Android)."""

import json
import urllib.request
from typing import Any, Dict, List, Optional


class RpcError(Exception):
    pass


def _check_url(url: str) -> str:
    url = url.strip()
    local = url.startswith(("http://127.0.0.1", "http://localhost"))
    if not (url.startswith("https://") or local):
        raise RpcError("RPC URL must start with https:// (plain http only for localhost)")
    return url


class RpcClient:
    def __init__(self, url: str, timeout: int = 25):
        self.url = _check_url(url)
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: Optional[list] = None) -> Any:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method,
                           "params": params or []}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "sos69069-msg/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp = json.load(r)
        except Exception as e:  # network / HTTP / JSON problems
            raise RpcError(f"{method}: {e}") from e
        if "error" in resp and resp["error"]:
            raise RpcError(f"{method}: {resp['error'].get('message', resp['error'])}")
        return resp.get("result")

    # ---- helpers ----
    def chain_id(self) -> int:
        return int(self.call("eth_chainId"), 16)

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def balance(self, addr: str) -> int:
        return int(self.call("eth_getBalance", [addr, "latest"]), 16)

    def nonce(self, addr: str) -> int:
        return int(self.call("eth_getTransactionCount", [addr, "pending"]), 16)

    def base_fee(self) -> int:
        blk = self.call("eth_getBlockByNumber", ["latest", False])
        return int(blk["baseFeePerGas"], 16)

    def priority_fee(self) -> int:
        try:
            return int(self.call("eth_maxPriorityFeePerGas"), 16)
        except RpcError:
            return 1_000_000_000

    def estimate_gas(self, frm: str, to: str, data: bytes) -> int:
        return int(self.call("eth_estimateGas",
                             [{"from": frm, "to": to, "data": "0x" + data.hex()}]), 16)

    def send_raw(self, raw: bytes) -> str:
        return self.call("eth_sendRawTransaction", ["0x" + raw.hex()])

    def receipt(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        return self.call("eth_getTransactionReceipt", [tx_hash])

    def get_logs(self, flt: Dict[str, Any]) -> List[Dict[str, Any]]:
        return self.call("eth_getLogs", [flt]) or []
