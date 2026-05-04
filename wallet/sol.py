"""Solana signing implementation."""

from nacl.signing import SigningKey

from ur.types import SolSignRequest, SolSignResult


def sign(signing_key: SigningKey, request: SolSignRequest) -> SolSignResult:
    """Sign request bytes with Ed25519 key.

    For both transaction and message sign types, the device signs the exact
    bytes supplied by the host wallet.
    """
    signed = signing_key.sign(request.sign_data)
    return SolSignResult(signature=bytes(signed.signature))
