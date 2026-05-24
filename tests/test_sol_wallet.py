from nacl.signing import VerifyKey
import pytest

from ur.types import SignType, SolSignRequest
from wallet import Wallet
from wallet.derive import derive_sol_accounts, derive_sol_address, derive_sol_signing_key

_TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_EXPECTED_SOL_PUBKEY = "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL"


def test_sol_derivation_vector_matches_expected_address():
    assert derive_sol_address(_TEST_MNEMONIC, index=0) == _EXPECTED_SOL_PUBKEY


def test_sol_accounts_include_expected_default_path():
    accounts = derive_sol_accounts(_TEST_MNEMONIC, count=2)
    assert accounts[0]["bip_path"] == "m/44'/501'/0'"
    assert accounts[1]["bip_path"] == "m/44'/501'/1'"
    assert accounts[0]["public_key"] == _EXPECTED_SOL_PUBKEY


def test_signing_uses_ed25519_and_verifies():
    request = SolSignRequest(
        request_id=b"\x11" * 16,
        sign_data=b"better-wallet-solana",
        derivation_path="m/44'/501'/0'",
        sign_type=SignType.MESSAGE,
    )
    wallet = Wallet(_TEST_MNEMONIC)
    result = wallet.sign(request)
    assert len(result.signature) == 64

    public_key = derive_sol_signing_key(_TEST_MNEMONIC, index=0).verify_key.encode()
    verify_key = VerifyKey(public_key)
    verify_key.verify(request.sign_data, result.signature)


def test_wallet_rejects_unknown_requested_address():
    request = SolSignRequest(
        request_id=b"\x22" * 16,
        sign_data=b"hello",
        derivation_path="m/44'/501'/0'",
        sign_type=SignType.MESSAGE,
        address=b"\xff" * 32,
    )
    wallet = Wallet(_TEST_MNEMONIC)
    try:
        wallet.sign(request)
        raise AssertionError("wallet.sign should have rejected unknown address")
    except ValueError as exc:
        assert "requested signer pubkey" in str(exc)


def test_wallet_uses_derivation_path_for_signer_selection():
    request = SolSignRequest(
        request_id=b"\x44" * 16,
        sign_data=b"path-index-1",
        derivation_path="m/44'/501'/1'",
        sign_type=SignType.MESSAGE,
    )
    wallet = Wallet(_TEST_MNEMONIC)
    result = wallet.sign(request)

    pubkey_index_1 = derive_sol_signing_key(_TEST_MNEMONIC, index=1).verify_key.encode()
    VerifyKey(pubkey_index_1).verify(request.sign_data, result.signature)


def test_wallet_rejects_address_path_mismatch():
    request = SolSignRequest(
        request_id=b"\x55" * 16,
        sign_data=b"mismatch",
        derivation_path="m/44'/501'/1'",
        sign_type=SignType.MESSAGE,
        address=derive_sol_signing_key(_TEST_MNEMONIC, index=0).verify_key.encode(),
    )
    wallet = Wallet(_TEST_MNEMONIC)
    with pytest.raises(ValueError, match="does not match derivation path"):
        wallet.sign(request)
