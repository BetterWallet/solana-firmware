"""
Core asyncio state machine.

This is the ONLY module that imports from wallet/.
The decrypted Account lives only in local scope during SIGNING state.
"""
import asyncio
import json
import logging
from pathlib import Path
import time
import uuid

from config import (
    DEVICE_LABEL,
    DEVICE_METADATA_PATH,
    KEYSTORE_PATH,
)
from solana import parser as sol_parser
from state.states import ButtonEvent, PINEvent, RenderEvent, State
from ur import decoder as ur_decoder_mod
from ur import encoder as ur_encoder
from ur.types import (
    SolAccount,
    SolAccountsPayload,
    SolDevice,
    SolSignRequest,
    SolSignature,
)

# wallet/ imports are deferred to local scope to make the boundary explicit
import wallet.keystore as keystore
from wallet import Wallet

log = logging.getLogger(__name__)
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


async def run(
    scan_queue: asyncio.Queue,
    event_queue: asyncio.Queue,
    render_queue: asyncio.Queue,
    camera_state: dict,
) -> None:
    """Main state machine coroutine. Run via asyncio.gather in main.py."""
    state = State.SETUP if not keystore.exists(KEYSTORE_PATH) else State.LOCKED
    wallet: Wallet | None = None
    ur_decoder = ur_decoder_mod.URDecoder()
    sign_request = None

    stats = camera_state.setdefault("stats", {})

    def _camera_on():
        camera_state["enabled"].set()

    def _camera_off():
        camera_state["enabled"].clear()
        camera_state["frame"] = None
        camera_state["scan_frame"] = None

    while True:
        try:
            if state == State.SETUP:
                state = await _handle_setup(event_queue, render_queue)

            elif state == State.LOCKED:
                state, wallet = await _handle_locked(event_queue, render_queue)

            elif state == State.IDLE:
                await render_queue.put(RenderEvent.idle(wallet.sol_address))
                state = await _handle_idle(event_queue)

            elif state == State.SCANNING:
                _camera_on()
                state, sign_request, ur_decoder = await _handle_scanning(
                    wallet, scan_queue, event_queue, render_queue, ur_decoder, stats
                )
                if state != State.SCANNING:
                    _camera_off()
                    _drain_queue(scan_queue)

            elif state == State.PARSED:
                state = await _handle_parsed(wallet, sign_request, render_queue)

            elif state == State.AWAIT_CONFIRM:
                state, ur_decoder, sign_request = await _handle_await_confirm(
                    event_queue, ur_decoder, sign_request
                )

            elif state == State.SIGNING:
                state, ur_decoder, sign_request = await _handle_signing(
                    wallet, sign_request, render_queue
                )

            elif state == State.DISPLAY_RESULT:
                _drain_queue(event_queue)
                await asyncio.sleep(1.0)   # ensure QR is visible before accepting input
                _drain_queue(event_queue)   # discard any bounce/hold events during delay
                await event_queue.get()
                ur_decoder = ur_decoder_mod.URDecoder()
                sign_request = None
                state = State.IDLE

            elif state == State.SHOW_IMPORT:
                state = await _handle_show_import(wallet, event_queue, render_queue)

            elif state == State.ERROR:
                _camera_off()
                wallet = None
                await event_queue.get()
                state = State.LOCKED

        except Exception as exc:
            _camera_off()
            log.exception("state machine error in state %s", state)
            await render_queue.put(RenderEvent.error(str(exc)))
            wallet = None
            state = State.ERROR


# ---------------------------------------------------------------------------
# State handlers
# ---------------------------------------------------------------------------

async def _handle_setup(event_queue: asyncio.Queue, render_queue: asyncio.Queue) -> State:
    """First-boot: generate mnemonic, show to user, create keystore, show import QR."""
    from wallet import keygen

    mnemonic = keygen.generate()
    words = mnemonic.split()
    await render_queue.put(RenderEvent.setup(words))

    # Wait for user to confirm they wrote down the words (CONFIRM button)
    while True:
        event = await event_queue.get()
        if event == ButtonEvent.CONFIRM:
            break

    # Collect a PIN
    await render_queue.put(RenderEvent.pin())
    try:
        pin = await _collect_pin(event_queue, render_queue)
    except _PINRejected:
        del mnemonic, words
        return State.SETUP   # restart setup with a new mnemonic

    keystore.save(KEYSTORE_PATH, mnemonic, pin)

    # Show Better Wallet account export QR immediately after setup.
    setup_wallet = Wallet(mnemonic)
    qr_frames = ur_encoder.encode_crypto_multi_accounts(
        _build_sol_accounts_payload(setup_wallet),
    )
    await render_queue.put(RenderEvent.result(qr_frames))
    log.info("setup complete — sol=%s", setup_wallet.sol_address)

    # Wait for user to confirm they scanned it
    await event_queue.get()

    # Securely discard secrets from local scope
    del mnemonic, words, setup_wallet

    return State.LOCKED


async def _handle_locked(
    event_queue: asyncio.Queue,
    render_queue: asyncio.Queue,
) -> tuple[State, Wallet]:
    while True:
        await render_queue.put(RenderEvent.pin())
        try:
            pin = await _collect_pin(event_queue, render_queue)
        except _PINRejected:
            continue   # clear digits and re-show PIN screen
        try:
            mnemonic = keystore.load(KEYSTORE_PATH, pin)
            return State.IDLE, Wallet(mnemonic)
        except ValueError:
            await render_queue.put(RenderEvent.wrong_pin())
            await asyncio.sleep(2)


async def _handle_idle(event_queue: asyncio.Queue) -> State:
    """Wait on idle screen for user to initiate scanning or show import QR."""
    while True:
        event = await event_queue.get()
        if event == ButtonEvent.CONFIRM:
            return State.SCANNING
        if event == ButtonEvent.REJECT:
            return State.SHOW_IMPORT


async def _handle_scanning(
    wallet: Wallet,
    scan_queue: asyncio.Queue,
    event_queue: asyncio.Queue,
    render_queue: asyncio.Queue,
    ur_decoder: ur_decoder_mod.URDecoder,
    stats: dict,
) -> tuple[State, object, ur_decoder_mod.URDecoder]:
    await render_queue.put(RenderEvent.scanning(0.0))

    # Check for REJECT button (cancel scan)
    try:
        event = event_queue.get_nowait()
        if event == ButtonEvent.REJECT:
            ur_decoder.reset()
            return State.IDLE, None, ur_decoder
    except asyncio.QueueEmpty:
        pass

    try:
        fragment = await asyncio.wait_for(scan_queue.get(), timeout=0.1)
        accepted, complete = ur_decoder.receive_part_info(fragment)
        stats["ur_parts_accepted"] = ur_decoder.accepted_parts
        stats["ur_parts_rejected"] = ur_decoder.rejected_parts
        progress = ur_decoder.progress()
        stats["last_progress"] = progress
        await render_queue.put(RenderEvent.scanning(progress))
        if not accepted:
            log.debug("rejected UR fragment while scanning")

        if complete:
            started_at = stats.get("scan_started_at")
            if started_at is not None:
                log.info("scan complete in %.2fs", asyncio.get_event_loop().time() - started_at)
            sign_request = ur_decoder.result()
            return State.PARSED, sign_request, ur_decoder
        return State.SCANNING, None, ur_decoder

    except asyncio.TimeoutError:
        return State.SCANNING, None, ur_decoder


async def _handle_parsed(wallet: Wallet, sign_request, render_queue: asyncio.Queue) -> State:
    if not isinstance(sign_request, SolSignRequest):
        raise ValueError(f"unsupported sign request type: {type(sign_request).__name__}")

    if sign_request.address:
        requested = wallet.find_sol_account(_sol_bytes_to_address(sign_request.address))
        if requested is None:
            raise ValueError("requested signer does not match any local Solana account")

    fields = sol_parser.parse(sign_request.sign_data, sign_request.sign_type, sign_request.address)
    await render_queue.put(RenderEvent.confirm(fields))
    return State.AWAIT_CONFIRM


async def _handle_await_confirm(
    event_queue: asyncio.Queue,
    ur_decoder: ur_decoder_mod.URDecoder,
    sign_request,
) -> tuple[State, ur_decoder_mod.URDecoder, object]:
    event = await event_queue.get()
    if event == ButtonEvent.CONFIRM:
        return State.SIGNING, ur_decoder, sign_request
    else:  # REJECT
        ur_decoder.reset()
        return State.IDLE, ur_decoder, None


async def _handle_signing(
    wallet: Wallet,
    sign_request,
    render_queue: asyncio.Queue,
) -> tuple[State, ur_decoder_mod.URDecoder, object]:
    await render_queue.put(RenderEvent.signing())

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, wallet.sign, sign_request)

    if not isinstance(sign_request, SolSignRequest):
        raise ValueError(f"unsupported sign request type: {type(sign_request).__name__}")

    sig = SolSignature(
        request_id=sign_request.request_id,
        signature=result.signature,
    )
    qr_frames = ur_encoder.encode_sol_signature(sig)
    await render_queue.put(RenderEvent.result(qr_frames))

    new_decoder = ur_decoder_mod.URDecoder()
    return State.DISPLAY_RESULT, new_decoder, None


async def _handle_show_import(
    wallet: Wallet,
    event_queue: asyncio.Queue,
    render_queue: asyncio.Queue,
) -> State:
    """Show the Better Wallet account export QR."""
    qr_frames = ur_encoder.encode_crypto_multi_accounts(
        _build_sol_accounts_payload(wallet),
    )
    # #region agent log
    _debug_log(
        "H5",
        "state/machine.py:_handle_show_import",
        "rendering import QR frames",
        {
            "frames_count": len(qr_frames),
            "first_frame_prefix": qr_frames[0][:40] if qr_frames else "",
        },
    )
    # #endregion
    await render_queue.put(RenderEvent.result(qr_frames))
    await event_queue.get()
    return State.IDLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _drain_queue(q: asyncio.Queue) -> None:
    """Discard any stale events already sitting in a queue."""
    while not q.empty():
        try:
            q.get_nowait()
        except asyncio.QueueEmpty:
            break


class _PINRejected(Exception):
    """Raised when user presses REJECT during PIN entry."""
    pass


async def _collect_pin(event_queue: asyncio.Queue, render_queue: asyncio.Queue) -> str:
    """
    Wait for a PINEvent from the event queue.
    Raises _PINRejected if the user presses REJECT during PIN entry.
    """
    while True:
        event = await event_queue.get()
        if isinstance(event, PINEvent):
            return event.pin
        if event == ButtonEvent.REJECT:
            raise _PINRejected()


def _build_sol_accounts_payload(wallet: Wallet) -> SolAccountsPayload:
    device_info = _load_or_create_device_metadata()
    exported_accounts = wallet.sol_accounts[:1]
    # #region agent log
    _debug_log(
        "H8",
        "state/machine.py:_build_sol_accounts_payload",
        "building account export payload",
        {
            "exported_accounts": len(exported_accounts),
            "total_wallet_accounts": len(wallet.sol_accounts),
        },
    )
    # #endregion
    return SolAccountsPayload(
        device=SolDevice(
            id=device_info["id"],
            label=device_info["label"],
        ),
        accounts=[
            SolAccount(
                public_key=account["public_key"],
                public_key_bytes=account["public_key_bytes"],
                bip_path=account["bip_path"],
                label=f"Account #{account['index'] + 1}",
            )
            for account in exported_accounts
        ],
    )


def _load_or_create_device_metadata() -> dict:
    device_file = Path(DEVICE_METADATA_PATH)
    if device_file.exists():
        try:
            stored = json.loads(device_file.read_text())
            if isinstance(stored, dict) and stored.get("id") and stored.get("label"):
                return stored
        except (OSError, json.JSONDecodeError):
            log.warning("device metadata file is unreadable; regenerating")

    generated = {
        "id": str(uuid.uuid4()),
        "label": DEVICE_LABEL,
    }
    device_file.parent.mkdir(parents=True, exist_ok=True)
    device_file.write_text(json.dumps(generated))
    return generated


def _sol_bytes_to_address(public_key_bytes: bytes) -> str:
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(public_key_bytes, "big")
    encoded = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(alphabet[rem])
    encoded.reverse()
    leading_zeros = len(public_key_bytes) - len(public_key_bytes.lstrip(b"\x00"))
    return ("1" * leading_zeros) + encoded.decode("ascii")


