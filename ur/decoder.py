"""UR fountain decoder for Solana sign requests."""

import cbor2
import uuid
from _bc_ur.ur_decoder import URDecoder as _URDecoder

from ur.types import SignType, SolSignRequest


def _decode_keypath(value) -> str:
    """Decode tagged crypto-keypath into derivation path string."""
    if isinstance(value, cbor2.CBORTag):
        value = value.value
    components = value.get(1, [])
    parts = []
    i = 0
    while i < len(components):
        comp = components[i]
        hardened = False
        if i + 1 < len(components):
            hardened = bool(components[i + 1])
        if isinstance(comp, list):
            parts.append("*")
        else:
            parts.append(f"{comp}'" if hardened else str(comp))
        i += 2
    return "m/" + "/".join(parts)


def _decode_uuid(value) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, cbor2.CBORTag):
        if isinstance(value.value, bytes):
            return value.value
        return bytes(value.value)
    if isinstance(value, bytes):
        return value
    if isinstance(value, uuid.UUID):
        return value.bytes
    return None


class URDecoder:
    """Wraps foundation-ur URDecoder. Feed string fragments, call result() when done.
    """

    def __init__(self):
        self._decoder = _URDecoder()
        self.accepted_parts = 0
        self.rejected_parts = 0
        self.last_part_accepted = False

    def receive_part(self, part: str) -> bool:
        _accepted, complete = self.receive_part_info(part)
        return complete

    def receive_part_info(self, part: str) -> tuple[bool, bool]:
        """Feed one QR payload (UR fragment). Returns (accepted, complete)."""
        accepted = self._decoder.receive_part(part)
        self.last_part_accepted = accepted
        if accepted:
            self.accepted_parts += 1
        else:
            self.rejected_parts += 1
        return accepted, self._decoder.is_complete()

    def is_complete(self) -> bool:
        return self._decoder.is_complete()

    def progress(self) -> float:
        try:
            return self._decoder.estimated_percent_complete()
        except AttributeError:
            return 1.0 if self._decoder.is_complete() else 0.0

    def result(self):
        """Return decoded Solana sign request. Call only when complete."""
        ur = self._decoder.result_ur()
        if ur.type == "sol-sign-request":
            return _parse_sol_sign_request(ur.cbor)
        raise ValueError(f"unexpected UR type: {ur.type!r}")

    def reset(self):
        self._decoder = _URDecoder()
        self.accepted_parts = 0
        self.rejected_parts = 0
        self.last_part_accepted = False

def _parse_sol_sign_request(cbor_bytes: bytes) -> SolSignRequest:
    data = cbor2.loads(cbor_bytes)
    if 2 not in data or 3 not in data:
        raise ValueError("sol-sign-request missing required keys")

    sign_type = SignType(data.get(6, int(SignType.TRANSACTION)))
    return SolSignRequest(
        request_id=_decode_uuid(data.get(1)),
        sign_data=data[2],
        derivation_path=_decode_keypath(data[3]),
        sign_type=sign_type,
        address=data.get(4),
        origin=data.get(5),
    )
