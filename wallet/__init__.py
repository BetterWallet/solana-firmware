"""Public wallet surface for Solana-only signing."""

from functools import cached_property

from ur.types import SolSignRequest

from wallet import derive as _derive
from wallet import sol as _sol


class Wallet:
    """Unlocked wallet holding the mnemonic in memory."""

    def __init__(self, mnemonic: str):
        self._mnemonic = mnemonic

    @cached_property
    def sol_accounts(self):
        return _derive.derive_sol_accounts(self._mnemonic)

    @property
    def sol_address(self) -> str:
        return self.sol_accounts[0]["public_key"]

    @cached_property
    def sol_master_fingerprint(self) -> bytes:
        return _derive.derive_sol_master_fingerprint(self._mnemonic)

    def find_sol_account(self, public_key: str):
        for account in self.sol_accounts:
            if account["public_key"] == public_key:
                return account
        return None

    def sign(self, request: SolSignRequest):
        if not isinstance(request, SolSignRequest):
            raise ValueError(f"unsupported sign request type: {type(request).__name__}")

        account_index = _account_index_from_path(request.derivation_path)
        account = next((entry for entry in self.sol_accounts if int(entry["index"]) == account_index), None)
        if account is None:
            raise ValueError("requested signer derivation path is not available on this device")

        if request.address:
            requested_address = _derive.sol_bytes_to_address(request.address)
            if requested_address != account["public_key"]:
                raise ValueError("requested signer pubkey does not match derivation path")

        signing_key = _derive.derive_sol_signing_key(self._mnemonic, index=account_index)
        return _sol.sign(signing_key, request)


def _account_index_from_path(path: str) -> int:
    normalized = path.strip()
    if normalized.startswith("m/"):
        normalized = normalized[2:]
    parts = normalized.split("/")
    if len(parts) != 3:
        raise ValueError(f"unsupported derivation path: {path}")
    if parts[0] != "44'" or parts[1] != "501'":
        raise ValueError(f"unsupported derivation path: {path}")
    account_part = parts[2]
    if not account_part.endswith("'"):
        raise ValueError(f"unsupported derivation path: {path}")
    return int(account_part[:-1])
