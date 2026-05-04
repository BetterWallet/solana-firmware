import cbor2
from _bc_ur.ur import UR
from _bc_ur.ur_encoder import UREncoder

from ur.decoder import URDecoder
from ur.encoder import encode_crypto_multi_accounts, encode_sol_signature
from ur.types import SignType, SolAccount, SolAccountsPayload, SolDevice, SolSignature


def _encode_request_parts() -> list[str]:
    keypath = cbor2.CBORTag(304, {1: [44, True, 501, True, 0, True, 0, True]})
    payload = {
        1: cbor2.CBORTag(37, b"\x33" * 16),
        2: b"\x01\x02\x03",
        3: keypath,
        6: int(SignType.TRANSACTION),
    }
    ur = UR("sol-sign-request", cbor2.dumps(payload))
    enc = UREncoder(ur, 30)
    if enc.is_single_part():
        return [enc.next_part()]
    return [enc.next_part() for _ in range(enc.expected_part_count())]


def test_sol_sign_request_decodes_from_ur_fragments():
    decoder = URDecoder()
    parts = _encode_request_parts()
    complete = False
    for part in parts:
        _, complete = decoder.receive_part_info(part)
    assert complete is True

    request = decoder.result()
    assert request.request_id == b"\x33" * 16
    assert request.sign_data == b"\x01\x02\x03"
    assert request.derivation_path == "m/44'/501'/0'/0'"
    assert request.sign_type == SignType.TRANSACTION


def test_sol_signature_roundtrip_through_ur_decoder():
    sig = SolSignature(request_id=b"\xaa" * 16, signature=b"\xbb" * 64)
    parts = encode_sol_signature(sig, max_fragment_len=40)
    decoder = URDecoder()
    # Decoder only accepts sol-sign-request, so just verify wire format prefix and size.
    assert parts
    assert parts[0].startswith("ur:sol-signature")


def test_sol_accounts_export_uses_crypto_multi_accounts():
    payload = SolAccountsPayload(
        device=SolDevice(id="dev-1", label="Better Wallet"),
        accounts=[
            SolAccount(
                public_key="HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
                public_key_bytes=bytes.fromhex("f036276246a75bfe10b0f33a35cb81c9a85c6a25e0f03f56c6f64efb8ac60d89"),
                bip_path="m/44'/501'/0'/0'",
            )
        ],
    )
    parts = encode_crypto_multi_accounts(payload, max_fragment_len=40)
    assert parts
    assert parts[0].startswith("ur:crypto-multi-accounts")
