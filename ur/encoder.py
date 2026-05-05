"""Encode Solana signatures/accounts into UR fountain-code strings."""

import cbor2
import hashlib
import json
import time
from _bc_ur.ur import UR
from _bc_ur.ur_encoder import UREncoder as _UREncoder

from config import MAX_FRAGMENT_LEN
from ur.types import SolAccountsPayload, SolSignature

_DEBUG_LOG_PATH = "/home/pi/solana-firmware/.cursor/debug-471b5b.log"


def _debug_log(hypothesis_id: str, location: str, message: str, data: dict) -> None:
    payload = {
        "sessionId": "471b5b",
        "runId": "pre-fix",
        "hypothesisId": hypothesis_id,
        "location": location,
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        with open(_DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, separators=(",", ":")) + "\n")
    except Exception:
        pass


def encode_sol_signature(sig: SolSignature, max_fragment_len: int = MAX_FRAGMENT_LEN) -> list[str]:
    payload = {2: sig.signature}
    if sig.request_id is not None:
        payload[1] = cbor2.CBORTag(37, sig.request_id)
    cbor_bytes = cbor2.dumps(payload)
    ur = UR("sol-signature", cbor_bytes)
    return _encode_to_parts(ur, max_fragment_len)


def _build_keypath(path_str: str, source_fingerprint: bytes | None = None) -> cbor2.CBORTag:
    components = []
    for part in path_str.split("/"):
        if not part or part == "m":
            continue
        if part == "*":
            components.append([])
            components.append(False)
            continue
        hardened = part.endswith("'")
        index = int(part.rstrip("'"))
        components.append(index)
        components.append(hardened)
    keypath = {1: components}
    if source_fingerprint:
        keypath[2] = int.from_bytes(source_fingerprint, "big")
    return cbor2.CBORTag(304, keypath)


def _account_label(account_path: str, fallback: str | None) -> str:
    if fallback:
        return fallback
    account_index = account_path.rstrip("'").split("/")[-1]
    return f"SOL-{account_index}"


def _build_hdkey_cbor(
    public_key_bytes: bytes,
    origin_path: str,
    label: str | None,
    source_fingerprint: bytes | None,
) -> dict:
    # Keystone's multi-account parser requires a derived key with an origin
    # path. Marking this as a master key causes the parser to drop the origin.
    return {
        2: False,  # is_private
        3: public_key_bytes,
        6: _build_keypath(origin_path, source_fingerprint),
        9: _account_label(origin_path, label),
        10: "SOL",
    }
    # #region agent log
    _debug_log(
        "H1",
        "ur/encoder.py:_build_hdkey_cbor",
        "built hdkey map (master flag omitted for derived key)",
        {
            "has_is_master_key": 1 in hdkey,
            "is_private": hdkey.get(2),
            "has_origin": 6 in hdkey,
            "source_fingerprint_hex": source_fingerprint.hex(),
        },
    )
    # #endregion
    return hdkey


def encode_crypto_multi_accounts(payload: SolAccountsPayload, max_fragment_len: int = MAX_FRAGMENT_LEN) -> list[str]:
    # #region agent log
    _debug_log(
        "H5",
        "ur/encoder.py:encode_crypto_multi_accounts:start",
        "building crypto-multi-accounts payload",
        {
            "account_count": len(payload.accounts),
            "device_label": payload.device.label,
            "max_fragment_len": max_fragment_len,
        },
    )
    # #endregion

    seed_account = payload.accounts[0] if payload.accounts else None
    fingerprint = b"\x00\x00\x00\x01"
    if seed_account is not None:
        digest = hashlib.sha256(seed_account.public_key_bytes).digest()
        fingerprint = digest[:4]
        if fingerprint == b"\x00\x00\x00\x00":
            fingerprint = b"\x00\x00\x00\x01"
    # #region agent log
    _debug_log(
        "H6,H7",
        "ur/encoder.py:encode_crypto_multi_accounts:fingerprint",
        "computed account export fingerprint",
        {
            "fingerprint_hex": fingerprint.hex(),
            "fingerprint_is_zero": fingerprint == b"\x00\x00\x00\x00",
        },
    )
    # #endregion

    hdkeys = []
    for account in payload.accounts:
        hdkeys.append(
            cbor2.CBORTag(
                303,
                _build_hdkey_cbor(
                    account.public_key_bytes,
                    account.bip_path,
                    account.label,
                    payload.master_fingerprint,
                ),
            )
        )

    account_payload = {
        1: int.from_bytes(payload.master_fingerprint, "big"),
        2: hdkeys,
        3: payload.device.label,
        4: payload.device.id,
    }
    if payload.device.fw_version:
        account_payload[5] = payload.device.fw_version

    cbor_bytes = cbor2.dumps(account_payload)
    ur = UR("crypto-multi-accounts", cbor_bytes)
    parts = _encode_to_parts(ur, max_fragment_len)
    # #region agent log
    _debug_log(
        "H1,H3,H5",
        "ur/encoder.py:encode_crypto_multi_accounts:result",
        "encoded crypto-multi-accounts ur parts",
        {
            "master_fingerprint": int.from_bytes(fingerprint, "big"),
            "master_fingerprint_hex": fingerprint.hex(),
            "parts_count": len(parts),
            "first_part_prefix": parts[0][:40] if parts else "",
            "cbor_size": len(cbor_bytes),
        },
    )
    # #endregion
    return parts


def _encode_to_parts(ur: UR, max_fragment_len: int) -> list[str]:
    """
    Collect enough parts from the fountain encoder for one full cycle.
    For single-part URs, returns one element.
    For multi-part URs, returns encoder.expected_part_count() parts.
    """
    encoder = _UREncoder(ur, max_fragment_len)
    if encoder.is_single_part():
        return [encoder.next_part()]

    count = encoder.expected_part_count()
    return [encoder.next_part() for _ in range(count)]
