from dataclasses import dataclass
from enum import IntEnum


class SignType(IntEnum):
    TRANSACTION = 1
    MESSAGE = 2


@dataclass
class SolSignRequest:
    request_id: bytes | None
    sign_data: bytes
    derivation_path: str
    sign_type: SignType
    address: bytes | None = None
    origin: str | None = None


@dataclass
class SolSignature:
    request_id: bytes | None
    signature: bytes


@dataclass
class SolSignResult:
    signature: bytes


@dataclass
class SolAccount:
    public_key: str
    public_key_bytes: bytes
    bip_path: str
    label: str | None = None


@dataclass
class SolDevice:
    id: str
    label: str
    fw_version: str | None = None


@dataclass
class SolAccountsPayload:
    device: SolDevice
    accounts: list[SolAccount]
    master_fingerprint: bytes = b"\x00\x00\x00\x00"
