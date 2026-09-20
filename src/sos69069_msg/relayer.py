"""Submit a signed record to the contract (you pay the gas from your relayer key)."""

import json
from typing import Any, Dict

from .abi import encode_record_signature
from .config import CHAIN_ID, CONTRACT_ADDRESS
from .eip712 import verify_record
from .ethcrypto import KeyPair, normalize_address
from .rpc import RpcClient, RpcError
from .tx import sign_eip1559


def _hex(s: str, n: int = None) -> bytes:
    b = bytes.fromhex(s.strip().removeprefix("0x"))
    if n is not None and len(b) != n:
        raise ValueError(f"expected {n} bytes, got {len(b)}")
    return b


def parse_record(text: str) -> Dict[str, Any]:
    """Parse + fully validate a record JSON from the Send tab (or from a stranger).
    The destination is ALWAYS our configured contract; the JSON's `to` is never trusted."""
    j = json.loads(text)
    if j.get("chainId", CHAIN_ID) != CHAIN_ID:
        raise ValueError("Record is for a different chain")
    if "to" in j and normalize_address(j["to"]) != normalize_address(CONTRACT_ADDRESS):
        raise ValueError("Record targets a different contract")
    rec = {
        "signer": normalize_address(j["signer"]),
        "intended_to": normalize_address(j["intendedTo"]),
        "payload_hash": _hex(j["payloadHash"], 32),
        "signature": _hex(j["signature"], 65),
        "metadata": j["metadata"],
    }
    if not verify_record(rec["signer"], rec["intended_to"], rec["payload_hash"],
                         rec["metadata"], rec["signature"]):
        raise ValueError("Signature does not verify for this record")
    return rec


def submit(rpc: RpcClient, relayer: KeyPair, rec: Dict[str, Any],
           max_fee_cap_gwei: float = 50.0) -> str:
    """Send recordSignature. Returns the tx hash. Refuses if gas is above the cap."""
    if rpc.chain_id() != CHAIN_ID:
        raise RpcError(f"RPC is on chain {rpc.chain_id()}, expected {CHAIN_ID} (mainnet)")
    data = encode_record_signature(rec["signer"], rec["intended_to"], rec["payload_hash"],
                                   rec["signature"], rec["metadata"])
    contract = normalize_address(CONTRACT_ADDRESS)

    prio = rpc.priority_fee()
    max_fee = 2 * rpc.base_fee() + prio
    if max_fee > int(max_fee_cap_gwei * 1e9):
        raise RpcError(f"Gas too high now ({max_fee / 1e9:.1f} gwei > cap {max_fee_cap_gwei} gwei)")
    # estimateGas also acts as a dry run: it reverts on duplicates / bad signatures
    gas = rpc.estimate_gas(relayer.address, contract, data) * 12 // 10
    need = gas * max_fee
    have = rpc.balance(relayer.address)
    if have < need:
        raise RpcError(f"Relayer {relayer.address} needs ≥ {need / 1e18:.5f} ETH (has {have / 1e18:.5f})")

    raw, tx_hash = sign_eip1559(relayer, CHAIN_ID, rpc.nonce(relayer.address), prio, max_fee,
                                gas, contract, 0, data)
    sent = rpc.send_raw(raw)
    return sent or "0x" + tx_hash.hex()
