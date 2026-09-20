"""Etherscan API (v2) log reader for the CHECK page.

Drop-in replacement for RpcClient where reader.scan()/sync() are concerned: it offers the
same two methods they use (block_number, get_logs) and returns logs in JSON-RPC format.

Notes
- Etherscan returns "0x" (empty hex) for the number zero (e.g. logIndex). That is normalised
  to "0x0", otherwise int(x, 16) fails and the log would be skipped silently.
- The API key is sent as a query parameter (Etherscan's design); it is scrubbed from any error
  text so it never shows up on screen.
- Range/result-window problems are reported with wording that reader._is_range_error()
  recognises, so scan() automatically retries with smaller block windows.
"""

import json
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List

from .rpc import RpcError

API_URL = "https://api.etherscan.io/v2/api"
PAGE_SIZE = 1000
RESULT_WINDOW = 10_000        # Etherscan: page * offset must stay <= 10000


def _hex(v: Any) -> str:
    """Normalise Etherscan hex quantities ("0x" -> "0x0", decimal -> hex)."""
    if v is None or v == "" or v == "0x":
        return "0x0"
    v = str(v)
    return v if v.startswith("0x") else hex(int(v))


class EtherscanClient:
    def __init__(self, api_key: str, chain_id: int = 1, timeout: int = 25):
        api_key = (api_key or "").strip()
        if not api_key:
            raise RpcError("Etherscan API key is empty")
        self.api_key = api_key
        self.chain_id = chain_id
        self.timeout = timeout

    # ---------------------------------------------------------------- http
    def _scrub(self, text: str) -> str:
        return str(text).replace(self.api_key, "***")

    def _get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        query = urllib.parse.urlencode({**params, "chainid": self.chain_id, "apikey": self.api_key})
        req = urllib.request.Request(f"{API_URL}?{query}", headers={"User-Agent": "sos69069-msg/0.3"})
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    j = json.load(r)
            except Exception as e:
                raise RpcError(f"Etherscan: {self._scrub(e)}") from e
            res = j.get("result")
            if isinstance(res, str) and "rate limit" in res.lower() and attempt < 2:
                time.sleep(1.2 * (attempt + 1))   # free tier: a few calls per second
                continue
            return j
        return j

    @staticmethod
    def _fail(j: Dict[str, Any]) -> RpcError:
        detail = j.get("result") if isinstance(j.get("result"), str) else j.get("message", "unknown error")
        return RpcError(f"Etherscan: {detail}")

    # ------------------------------------------------------------ interface
    def block_number(self) -> int:
        j = self._get({"module": "proxy", "action": "eth_blockNumber"})
        res = j.get("result")
        if isinstance(res, str) and res.startswith("0x"):
            return int(res, 16) if res != "0x" else 0
        # fallback: newest block at "now"
        j = self._get({"module": "block", "action": "getblocknobytime",
                       "timestamp": int(time.time()), "closest": "before"})
        if str(j.get("status")) == "1" and str(j.get("result", "")).isdigit():
            return int(j["result"])
        raise self._fail(j)

    def get_logs(self, flt: Dict[str, Any]) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {
            "module": "logs", "action": "getLogs",
            "fromBlock": int(flt["fromBlock"], 16) if str(flt["fromBlock"]).startswith("0x") else flt["fromBlock"],
            "toBlock": int(flt["toBlock"], 16) if str(flt["toBlock"]).startswith("0x") else flt["toBlock"],
        }
        if flt.get("address"):
            params["address"] = flt["address"]
        used = [i for i, t in enumerate(flt.get("topics") or []) if t]
        for i in used:
            params[f"topic{i}"] = flt["topics"][i]
        for a in used:                       # Etherscan needs an operator between each topic pair
            for b in used:
                if a < b:
                    params[f"topic{a}_{b}_opr"] = "and"

        out: List[Dict[str, Any]] = []
        page = 1
        while True:
            j = self._get({**params, "page": page, "offset": PAGE_SIZE})
            rows = j.get("result")
            if str(j.get("status")) != "1" or not isinstance(rows, list):
                msg = str(j.get("message", "")) + " " + (rows if isinstance(rows, str) else "")
                if "no records" in msg.lower() or (isinstance(rows, list) and not rows):
                    return out               # empty result is not an error
                raise self._fail(j)
            for r in rows:
                out.append({
                    "address": r.get("address"),
                    "topics": r.get("topics", []),
                    "data": r.get("data", "0x"),
                    "blockNumber": _hex(r.get("blockNumber")),
                    "logIndex": _hex(r.get("logIndex")),
                    "transactionHash": r.get("transactionHash", ""),
                    "timeStamp": _hex(r.get("timeStamp")),
                })
            if len(rows) < PAGE_SIZE:
                return out
            if page * PAGE_SIZE >= RESULT_WINDOW:
                # too many results for one window: ask the caller to use a smaller block range
                raise RpcError("Etherscan: result window too large (10000 records); "
                               "use a smaller block range")
            page += 1
