"""Parse Solana signing payload bytes into display fields."""

import hashlib

from display.fields import DisplayField
from ur.types import SignType

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_SYSTEM_PROGRAM_BYTES = b"\x00" * 32


def _to_b58(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    encoded = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(_B58_ALPHABET[rem])
    encoded.reverse()
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeros) + encoded.decode("ascii")


def _read_shortvec(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("shortvec overrun")
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, offset
        shift += 7
        if shift > 28:
            raise ValueError("shortvec too large")


def parse(sign_data: bytes, sign_type: SignType, address: bytes | None = None) -> list[DisplayField]:
    fields: list[DisplayField] = [
        DisplayField("Chain", "Solana"),
        DisplayField("Sign Type", "Transaction" if int(sign_type) == int(SignType.TRANSACTION) else "Message"),
        DisplayField("Payload Bytes", str(len(sign_data))),
        DisplayField("Payload SHA256", hashlib.sha256(sign_data).hexdigest()),
    ]
    if address:
        fields.append(DisplayField("Requested Signer", _to_b58(address)))

    if int(sign_type) == int(SignType.MESSAGE):
        _append_message_fields(fields, sign_data)
        return fields

    try:
        parsed = _parse_legacy_message(sign_data)
        fields.extend(parsed)
    except Exception:
        fields.append(DisplayField("Transaction", "Unable to decode, showing raw bytes"))
        fields.append(DisplayField("Raw Hex", sign_data.hex()))
    return fields


def _append_message_fields(fields: list[DisplayField], sign_data: bytes) -> None:
    fields.append(DisplayField("Message", sign_data.hex()))
    try:
        as_utf8 = sign_data.decode("utf-8")
        fields.append(DisplayField("Message UTF-8", as_utf8))
    except UnicodeDecodeError:
        fields.append(DisplayField("Message UTF-8", "(not utf-8)"))


def _parse_legacy_message(message: bytes) -> list[DisplayField]:
    if len(message) < 3:
        raise ValueError("message too short")
    num_required = message[0]
    readonly_signed = message[1]
    readonly_unsigned = message[2]
    offset = 3

    account_count, offset = _read_shortvec(message, offset)
    account_keys: list[bytes] = []
    for _ in range(account_count):
        if offset + 32 > len(message):
            raise ValueError("missing account bytes")
        account_keys.append(message[offset : offset + 32])
        offset += 32

    if offset + 32 > len(message):
        raise ValueError("missing recent blockhash")
    recent_blockhash = message[offset : offset + 32]
    offset += 32

    instruction_count, offset = _read_shortvec(message, offset)

    fields = [
        DisplayField("Required Signers", str(num_required)),
        DisplayField("Readonly Signed", str(readonly_signed)),
        DisplayField("Readonly Unsigned", str(readonly_unsigned)),
        DisplayField("Account Count", str(account_count)),
        DisplayField("Recent Blockhash", _to_b58(recent_blockhash)),
        DisplayField("Instructions", str(instruction_count)),
    ]

    for i in range(instruction_count):
        if offset >= len(message):
            raise ValueError("instruction overrun")
        program_id_index = message[offset]
        offset += 1
        account_idx_count, offset = _read_shortvec(message, offset)
        if offset + account_idx_count > len(message):
            raise ValueError("instruction account index overrun")
        account_indices = list(message[offset : offset + account_idx_count])
        offset += account_idx_count
        data_len, offset = _read_shortvec(message, offset)
        if offset + data_len > len(message):
            raise ValueError("instruction data overrun")
        ix_data = message[offset : offset + data_len]
        offset += data_len

        fields.append(DisplayField(f"Instruction {i + 1}", "", indent=0))
        if program_id_index >= len(account_keys):
            fields.append(DisplayField("Program", f"unknown-index:{program_id_index}", indent=1))
            fields.append(DisplayField("Data", ix_data.hex(), indent=1))
            continue

        program_key = account_keys[program_id_index]
        program_id = _to_b58(program_key)
        fields.append(DisplayField("Program", program_id, indent=1))

        if program_key == _SYSTEM_PROGRAM_BYTES and len(ix_data) >= 12:
            instruction_type = int.from_bytes(ix_data[:4], "little")
            if instruction_type == 2 and len(account_indices) >= 2:
                lamports = int.from_bytes(ix_data[4:12], "little")
                sender = _to_b58(account_keys[account_indices[0]])
                recipient = _to_b58(account_keys[account_indices[1]])
                fields.append(DisplayField("Type", "System Transfer", indent=1))
                fields.append(DisplayField("From", sender, indent=1))
                fields.append(DisplayField("To", recipient, indent=1))
                fields.append(DisplayField("Amount", f"{lamports / 1_000_000_000:.9f} SOL", indent=1))
                continue

        fields.append(DisplayField("Accounts", ", ".join(str(idx) for idx in account_indices), indent=1))
        fields.append(DisplayField("Data", ix_data.hex(), indent=1))

    return fields
