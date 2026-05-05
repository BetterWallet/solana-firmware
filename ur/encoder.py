"""Encode Solana signatures/accounts into UR fountain-code strings."""

import cbor2
from _bc_ur.ur import UR
from _bc_ur.ur_encoder import UREncoder as _UREncoder

from config import MAX_FRAGMENT_LEN
from ur.types import SolAccountsPayload, SolSignature


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


def encode_crypto_multi_accounts(payload: SolAccountsPayload, max_fragment_len: int = MAX_FRAGMENT_LEN) -> list[str]:
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
    return _encode_to_parts(ur, max_fragment_len)


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
