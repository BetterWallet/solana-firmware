"""Parse Solana signing payload bytes into display fields.

Supports both legacy and versioned (v0) transaction messages via solders.
Address lookup tables (ALTs) in v0 messages are surfaced so the user can
see which on-chain lookup tables are involved even though we cannot resolve
their contents without network access.
"""

import hashlib

from solders.message import (
    Message as LegacyMessage,
    MessageV0,
    from_bytes_versioned,
)
from solders.pubkey import Pubkey

from display.fields import DisplayField
from ur.types import SignType

_SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"


def parse(sign_data: bytes, sign_type: SignType, address: bytes | None = None) -> list[DisplayField]:
    fields: list[DisplayField] = [
        DisplayField("Chain", "Solana"),
        DisplayField("Sign Type", "Transaction" if int(sign_type) == int(SignType.TRANSACTION) else "Message"),
        DisplayField("Payload Bytes", str(len(sign_data))),
        DisplayField("Payload SHA256", hashlib.sha256(sign_data).hexdigest()),
    ]
    if address:
        fields.append(DisplayField("Requested Signer", str(Pubkey.from_bytes(address))))

    if int(sign_type) == int(SignType.MESSAGE):
        _append_message_fields(fields, sign_data)
        return fields

    try:
        msg = from_bytes_versioned(sign_data)
        if isinstance(msg, LegacyMessage):
            fields.extend(_fields_from_legacy(msg))
        elif isinstance(msg, MessageV0):
            fields.extend(_fields_from_v0(msg))
        else:
            raise ValueError(f"unexpected message type: {type(msg)}")
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


def _fields_from_legacy(msg: LegacyMessage) -> list[DisplayField]:
    account_keys = [str(k) for k in msg.account_keys]
    fields = _common_header_fields(msg, "Legacy", account_keys)
    fields.extend(_instruction_fields(msg.instructions, account_keys))
    return fields


def _fields_from_v0(msg: MessageV0) -> list[DisplayField]:
    """Parse a v0 versioned message, surfacing address lookup tables."""
    # Build the full account index map: static accounts first, then ALT slots.
    # Instruction account indices beyond the static list reference ALT entries.
    account_index_map = _build_v0_account_map(msg)
    static_keys = [str(k) for k in msg.account_keys]

    fields = _common_header_fields(msg, "v0", static_keys)

    atls = msg.address_table_lookups
    if atls:
        fields.append(DisplayField("Lookup Tables", str(len(atls))))
        for j, atl in enumerate(atls):
            fields.append(DisplayField(f"ALT {j + 1}", str(atl.account_key), indent=1))
            if atl.writable_indexes:
                fields.append(DisplayField(
                    "Writable Indexes",
                    ", ".join(str(x) for x in atl.writable_indexes),
                    indent=2,
                ))
            if atl.readonly_indexes:
                fields.append(DisplayField(
                    "Readonly Indexes",
                    ", ".join(str(x) for x in atl.readonly_indexes),
                    indent=2,
                ))

    fields.extend(_instruction_fields(msg.instructions, account_index_map))
    return fields


def _build_v0_account_map(msg: MessageV0) -> list[str]:
    """Return a list where index i maps to a human-readable account label.

    Indices 0..len(static)-1 are resolved pubkeys.
    Higher indices come from ALT writable entries then ALT readonly entries,
    labelled so the user knows they are unresolved lookup-table slots.
    """
    result = [str(k) for k in msg.account_keys]
    for j, atl in enumerate(msg.address_table_lookups):
        for k in atl.writable_indexes:
            result.append(f"ALT[{j}].writable[{k}]")
        for k in atl.readonly_indexes:
            result.append(f"ALT[{j}].readonly[{k}]")
    return result


def _common_header_fields(
    msg: LegacyMessage | MessageV0,
    version_label: str,
    static_keys: list[str],
) -> list[DisplayField]:
    h = msg.header
    return [
        DisplayField("Version", version_label),
        DisplayField("Required Signers", str(h.num_required_signatures)),
        DisplayField("Readonly Signed", str(h.num_readonly_signed_accounts)),
        DisplayField("Readonly Unsigned", str(h.num_readonly_unsigned_accounts)),
        DisplayField("Account Count", str(len(static_keys))),
        DisplayField("Recent Blockhash", str(msg.recent_blockhash)),
        DisplayField("Instructions", str(len(msg.instructions))),
    ]


def _instruction_fields(instructions, account_index_map: list[str]) -> list[DisplayField]:
    fields: list[DisplayField] = []
    for i, ix in enumerate(instructions):
        program_idx = ix.program_id_index
        accounts = list(ix.accounts)
        data = bytes(ix.data)

        fields.append(DisplayField(f"Instruction {i + 1}", "", indent=0))

        program_id = (
            account_index_map[program_idx]
            if program_idx < len(account_index_map)
            else f"unknown-index:{program_idx}"
        )
        fields.append(DisplayField("Program", program_id, indent=1))

        if program_id == _SYSTEM_PROGRAM_ID and len(data) >= 12 and len(accounts) >= 2:
            instruction_type = int.from_bytes(data[:4], "little")
            if instruction_type == 2:
                lamports = int.from_bytes(data[4:12], "little")
                sender_idx, recipient_idx = accounts[0], accounts[1]
                sender = (
                    account_index_map[sender_idx]
                    if sender_idx < len(account_index_map)
                    else f"index:{sender_idx}"
                )
                recipient = (
                    account_index_map[recipient_idx]
                    if recipient_idx < len(account_index_map)
                    else f"index:{recipient_idx}"
                )
                fields.append(DisplayField("Type", "System Transfer", indent=1))
                fields.append(DisplayField("From", sender, indent=1))
                fields.append(DisplayField("To", recipient, indent=1))
                fields.append(DisplayField("Amount", f"{lamports / 1_000_000_000:.9f} SOL", indent=1))
                continue

        resolved = [
            account_index_map[idx] if idx < len(account_index_map) else f"index:{idx}"
            for idx in accounts
        ]
        fields.append(DisplayField("Accounts", ", ".join(resolved), indent=1))
        fields.append(DisplayField("Data", data.hex(), indent=1))

    return fields
