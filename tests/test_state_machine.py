"""Tests for Solana-focused state.machine handlers."""

import asyncio
import pytest

from state.states import ButtonEvent, RenderEvent, State
from ur.types import SignType, SolSignRequest

_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


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


def _legacy_transfer_message() -> bytes:
    sender = bytes(range(1, 33))
    recipient = bytes(range(101, 133))
    system_program = b"\x00" * 32
    blockhash = b"\x08" * 32
    transfer_data = (2).to_bytes(4, "little") + (1_000_000_000).to_bytes(8, "little")
    instruction = bytes([2]) + _shortvec(2) + bytes([0, 1]) + _shortvec(12) + transfer_data
    return bytes([1, 0, 1]) + _shortvec(3) + sender + recipient + system_program + blockhash + _shortvec(1) + instruction


async def _drain_renders(q: asyncio.Queue) -> list[RenderEvent]:
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    return events


def _request() -> SolSignRequest:
    return SolSignRequest(
        request_id=b"\x99" * 16,
        sign_data=_legacy_transfer_message(),
        derivation_path="m/44'/501'/0'",
        sign_type=SignType.TRANSACTION,
    )


@pytest.mark.asyncio
async def test_handle_await_confirm_confirm():
    from state.machine import _handle_await_confirm
    from ur.decoder import URDecoder

    event_queue = asyncio.Queue()
    await event_queue.put(ButtonEvent.CONFIRM)
    state, _, req = await _handle_await_confirm(event_queue, URDecoder(), _request())
    assert state == State.SIGNING
    assert isinstance(req, SolSignRequest)


@pytest.mark.asyncio
async def test_handle_await_confirm_reject():
    from state.machine import _handle_await_confirm
    from ur.decoder import URDecoder

    event_queue = asyncio.Queue()
    await event_queue.put(ButtonEvent.REJECT)
    state, _, req = await _handle_await_confirm(event_queue, URDecoder(), _request())
    assert state == State.IDLE
    assert req is None


@pytest.mark.asyncio
async def test_handle_parsed_renders_confirm_fields():
    from state.machine import _handle_parsed
    from wallet import Wallet

    render_queue = asyncio.Queue()
    wallet = Wallet(_MNEMONIC)
    state = await _handle_parsed(wallet, _request(), render_queue)
    assert state == State.AWAIT_CONFIRM
    renders = await _drain_renders(render_queue)
    confirm = next(r for r in renders if r.screen == "confirm")
    assert confirm.data["fields"]
    assert any(f.label == "Chain" and f.value == "Solana" for f in confirm.data["fields"])


@pytest.mark.asyncio
async def test_handle_signing_emits_sol_signature_qr():
    from state.machine import _handle_signing
    from wallet import Wallet

    render_queue = asyncio.Queue()
    wallet = Wallet(_MNEMONIC)
    state, _, req = await _handle_signing(wallet, _request(), render_queue)
    assert state == State.DISPLAY_RESULT
    assert req is None
    renders = await _drain_renders(render_queue)
    result = next(r for r in renders if r.screen == "result")
    assert result.data["qr_frames"][0].startswith("ur:sol-signature")


@pytest.mark.asyncio
async def test_handle_show_import_emits_multi_accounts_qr():
    from state.machine import _handle_show_import
    from wallet import Wallet

    wallet = Wallet(_MNEMONIC)
    event_queue = asyncio.Queue()
    render_queue = asyncio.Queue()
    await event_queue.put(ButtonEvent.CONFIRM)
    next_state = await _handle_show_import(wallet, event_queue, render_queue)
    assert next_state == State.IDLE
    renders = await _drain_renders(render_queue)
    result = next(r for r in renders if r.screen == "result")
    assert result.data["qr_frames"][0].startswith("ur:crypto-multi-accounts")


def test_device_metadata_recreates_when_corrupt(tmp_path, monkeypatch):
    from state import machine

    device_path = tmp_path / "device.json"
    device_path.write_text("{ bad-json")
    monkeypatch.setattr(machine, "DEVICE_METADATA_PATH", str(device_path))
    metadata = machine._load_or_create_device_metadata()
    assert metadata["id"]
    assert metadata["label"]
