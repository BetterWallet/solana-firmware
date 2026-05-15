"""Tests for solana/parser.py — covers legacy, v0, ALT, message, and fallback paths."""

from solana.parser import parse
from ur.types import SignType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shortvec(value: int) -> bytes:
    out = bytearray()
    while True:
        elem = value & 0x7F
        value >>= 7
        if value:
            out.append(elem | 0x80)
        else:
            out.append(elem)
            return bytes(out)


def _build_legacy_transfer_message() -> bytes:
    sender = bytes(range(1, 33))
    recipient = bytes(range(101, 133))
    system_program = b"\x00" * 32
    recent_blockhash = b"\x09" * 32

    instruction_data = (2).to_bytes(4, "little") + (1_000_000_000).to_bytes(8, "little")
    instruction = (
        bytes([2])  # program index (system program at index 2)
        + _shortvec(2)
        + bytes([0, 1])
        + _shortvec(len(instruction_data))
        + instruction_data
    )

    return (
        bytes([1, 0, 1])  # header
        + _shortvec(3)
        + sender
        + recipient
        + system_program
        + recent_blockhash
        + _shortvec(1)
        + instruction
    )


def _build_v0_message_with_alt() -> bytes:
    """Build a minimal v0 message containing one address lookup table."""
    sender = bytes(range(1, 33))
    fake_program = bytes(range(50, 82))
    recent_blockhash = b"\xab" * 32

    ix_data = b"\x04\x05\x06"
    instruction = (
        bytes([1])          # program_id_index: fake_program at static index 1
        + _shortvec(1)      # 1 account operand
        + bytes([2])        # account at index 2 — comes from ALT writable slot
        + _shortvec(len(ix_data))
        + ix_data
    )

    alt_pubkey = bytes(range(200, 232))
    alt_lookup = (
        alt_pubkey          # 32-byte ALT address
        + _shortvec(1)      # 1 writable index
        + bytes([7])        # writable index 7 inside the ALT
        + _shortvec(1)      # 1 readonly index
        + bytes([3])        # readonly index 3 inside the ALT
    )

    return (
        bytes([0x80])       # v0 version prefix
        + bytes([1, 0, 0])  # header: 1 required signer, 0 readonly signed, 0 readonly unsigned
        + _shortvec(2)      # 2 static accounts
        + sender
        + fake_program
        + recent_blockhash
        + _shortvec(1)      # 1 instruction
        + instruction
        + _shortvec(1)      # 1 ALT
        + alt_lookup
    )


def _build_v0_message_no_alt() -> bytes:
    """Build a minimal v0 message with no address lookup tables."""
    sender = bytes(range(1, 33))
    system_program = b"\x00" * 32
    recent_blockhash = b"\xcc" * 32

    instruction_data = (2).to_bytes(4, "little") + (500_000_000).to_bytes(8, "little")
    instruction = (
        bytes([1])          # program_id_index: system program at static index 1
        + _shortvec(2)
        + bytes([0, 0])
        + _shortvec(len(instruction_data))
        + instruction_data
    )

    return (
        bytes([0x80])       # v0 version prefix
        + bytes([1, 0, 1])  # header
        + _shortvec(2)      # 2 static accounts
        + sender
        + system_program
        + recent_blockhash
        + _shortvec(1)
        + instruction
        + _shortvec(0)      # 0 ALTs
    )


# ---------------------------------------------------------------------------
# Legacy tests
# ---------------------------------------------------------------------------

def test_parser_decodes_system_transfer():
    message = _build_legacy_transfer_message()
    fields = parse(message, SignType.TRANSACTION)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Chain"] == "Solana"
    assert by_label["Sign Type"] == "Transaction"
    assert by_label["Version"] == "Legacy"
    assert by_label["Type"] == "System Transfer"
    assert by_label["Amount"] == "1.000000000 SOL"


def test_parser_legacy_shows_blockhash_and_accounts():
    message = _build_legacy_transfer_message()
    fields = parse(message, SignType.TRANSACTION)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Recent Blockhash"]  # non-empty base58
    assert by_label["Account Count"] == "3"
    assert by_label["Instructions"] == "1"


def test_parser_legacy_requested_signer():
    message = _build_legacy_transfer_message()
    signer_bytes = bytes(range(1, 33))
    fields = parse(message, SignType.TRANSACTION, address=signer_bytes)
    by_label = {f.label: f.value for f in fields if f.value}
    assert "Requested Signer" in by_label
    # Solana base58 pubkeys are 32–44 characters
    assert 32 <= len(by_label["Requested Signer"]) <= 44


# ---------------------------------------------------------------------------
# v0 tests
# ---------------------------------------------------------------------------

def test_parser_decodes_v0_message_with_alt():
    message = _build_v0_message_with_alt()
    fields = parse(message, SignType.TRANSACTION)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Chain"] == "Solana"
    assert by_label["Version"] == "v0"
    assert by_label["Lookup Tables"] == "1"
    assert "ALT 1" in by_label


def test_parser_v0_alt_writable_and_readonly_indexes():
    message = _build_v0_message_with_alt()
    fields = parse(message, SignType.TRANSACTION)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Writable Indexes"] == "7"
    assert by_label["Readonly Indexes"] == "3"


def test_parser_v0_instruction_accounts_reference_alt_slots():
    """Account at index 2 in a v0 message with 2 static keys should resolve to an ALT slot."""
    message = _build_v0_message_with_alt()
    fields = parse(message, SignType.TRANSACTION)
    account_values = [f.value for f in fields if f.label == "Accounts"]
    # The instruction uses account index 2, which is the first ALT writable slot
    assert any("ALT[0].writable" in v for v in account_values)


def test_parser_decodes_v0_no_alt():
    message = _build_v0_message_no_alt()
    fields = parse(message, SignType.TRANSACTION)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Version"] == "v0"
    assert "Lookup Tables" not in by_label


# ---------------------------------------------------------------------------
# Message (off-chain signing) tests
# ---------------------------------------------------------------------------

def test_parser_handles_message_sign_type():
    fields = parse(b"hello-solana", SignType.MESSAGE)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Sign Type"] == "Message"
    assert by_label["Message UTF-8"] == "hello-solana"


def test_parser_message_non_utf8():
    fields = parse(b"\xff\xfe\xfd", SignType.MESSAGE)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Message UTF-8"] == "(not utf-8)"


# ---------------------------------------------------------------------------
# Fallback / corrupt-payload test
# ---------------------------------------------------------------------------

def test_parser_falls_back_on_garbage():
    fields = parse(b"\xde\xad\xbe\xef", SignType.TRANSACTION)
    by_label = {f.label: f.value for f in fields if f.value}
    assert "Transaction" in by_label
    assert "Raw Hex" in by_label
    assert by_label["Raw Hex"] == "deadbeef"
