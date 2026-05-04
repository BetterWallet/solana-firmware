from solana.parser import parse
from ur.types import SignType


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
        bytes([2])  # program index
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


def test_parser_decodes_system_transfer():
    message = _build_legacy_transfer_message()
    fields = parse(message, SignType.TRANSACTION)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Chain"] == "Solana"
    assert by_label["Sign Type"] == "Transaction"
    assert by_label["Type"] == "System Transfer"
    assert by_label["Amount"] == "1.000000000 SOL"


def test_parser_handles_message_sign_type():
    fields = parse(b"hello-solana", SignType.MESSAGE)
    by_label = {f.label: f.value for f in fields if f.value}
    assert by_label["Sign Type"] == "Message"
    assert by_label["Message UTF-8"] == "hello-solana"
