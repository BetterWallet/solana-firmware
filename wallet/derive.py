"""Solana HD derivation from a single BIP-39 mnemonic."""

import hashlib
import hmac
from mnemonic import Mnemonic
from nacl.signing import SigningKey

try:
    from config import SOL_ACCOUNT_COUNT, SOL_DERIVATION_PATH_TEMPLATE
except ImportError:
    SOL_ACCOUNT_COUNT = 5
    SOL_DERIVATION_PATH_TEMPLATE = "m/44'/501'/{i}'/0'"


_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_MNEMO = Mnemonic("english")
_HARDENED = 0x80000000


def _to_b58(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    encoded = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(_B58_ALPHABET[rem])
    encoded.reverse()
    leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return ("1" * leading_zeros) + encoded.decode("ascii")


def _slip10_master_key(seed: bytes) -> tuple[bytes, bytes]:
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def _slip10_ckd_priv(parent_key: bytes, parent_chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    data = b"\x00" + parent_key + index.to_bytes(4, "big")
    digest = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def _derive_private_key(mnemonic: str, index: int) -> bytes:
    """Derive ed25519 private key for m/44'/501'/{index}'/0'."""
    seed_bytes = _MNEMO.to_seed(mnemonic, passphrase="")
    key, chain_code = _slip10_master_key(seed_bytes)
    for hardened in (44, 501, index, 0):
        key, chain_code = _slip10_ckd_priv(key, chain_code, hardened + _HARDENED)
    return key


def derive_sol_signing_key(mnemonic: str, index: int = 0) -> SigningKey:
    """Derive nacl SigningKey for Solana path m/44'/501'/{index}'/0'."""
    private_key_bytes = _derive_private_key(mnemonic, index=index)
    return SigningKey(private_key_bytes)


def derive_sol_public_key_bytes(mnemonic: str, index: int = 0) -> bytes:
    """Derive raw 32-byte Solana Ed25519 public key."""
    signing_key = derive_sol_signing_key(mnemonic, index=index)
    return signing_key.verify_key.encode()


def derive_sol_address(mnemonic: str, index: int = 0) -> str:
    """Derive base58 Solana address (ed25519 public key)."""
    public_key_bytes = derive_sol_public_key_bytes(mnemonic, index=index)
    return _to_b58(public_key_bytes)


def sol_bytes_to_address(public_key_bytes: bytes) -> str:
    return _to_b58(public_key_bytes)


def derive_sol_accounts(mnemonic: str, count: int = SOL_ACCOUNT_COUNT) -> list[dict]:
    """Derive account metadata list for export UI/QR."""
    accounts = []
    for index in range(count):
        accounts.append(
            {
                "index": index,
                "public_key": derive_sol_address(mnemonic, index=index),
                "public_key_bytes": derive_sol_public_key_bytes(mnemonic, index=index),
                "bip_path": SOL_DERIVATION_PATH_TEMPLATE.format(i=index),
            }
        )
    return accounts
