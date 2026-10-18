"""TokenWallet — Token UTXO management for fungible token contracts.

Manages token UTXOs for a fungible token contract. Assumes the artifact
describes a token contract with:
- A `transfer` public method.
- A state field named `balance`, `supply`, or `amount` of type int/bigint.

This is a higher-level convenience wrapper around RunarContract for the
common token use-case.
"""

from __future__ import annotations

import warnings

from runar.sdk.types import RunarArtifact, Utxo
from runar.sdk.provider import Provider
from runar.sdk.signer import Signer
from runar.sdk.contract import RunarContract
from runar.sdk.deployment import build_p2pkh_script
from runar.sdk.errors import MalformedScriptError
from runar.sdk.script_utils import matches_artifact
from runar.sdk.state import find_last_op_return


# N-239 (user decision R92): ``merge`` and ``transfer`` drive an ABI that
# cannot be made sound, so they are deprecated rather than redesigned or
# removed. ``warnings`` reports each once per call site by default.
_MERGE_DEPRECATION = (
    'runar-sdk: TokenWallet.merge is deprecated and unsafe. Its '
    'merge(sig, otherSupply, otherHolder) ABI cannot authenticate the '
    'companion input, so a holder can call merge on ONE input with a made-up '
    'otherSupply (supply inflation). Use the token-ft example '
    '(FungibleTokenExample, examples/*/token-ft/) instead (N-239).'
)
_TRANSFER_DEPRECATION = (
    'runar-sdk: TokenWallet.transfer is deprecated and unsafe. Its '
    'transfer(sig, to: Addr) ABI cannot re-key the PubKey holder from an '
    'Addr, so the token stays with the current holder instead of moving to '
    'the recipient. Use the token-ft example (FungibleTokenExample, '
    'examples/*/token-ft/) instead (N-239).'
)


class TokenWallet:
    """Manages token UTXOs for a fungible token contract."""

    def __init__(
        self,
        artifact: RunarArtifact,
        provider: Provider,
        signer: Signer,
    ):
        self.artifact = artifact
        self.provider = provider
        self.signer = signer

    def get_balance(self) -> int:
        """Get the total token balance across all UTXOs belonging to this wallet."""
        utxos = self.get_utxos()
        total = 0

        for utxo in utxos:
            contract = RunarContract.from_txid(
                self.artifact,
                utxo.txid,
                utxo.output_index,
                self.provider,
            )
            state = contract.get_state()
            # Look for a supply/balance/amount field in the state
            balance_field = (
                state.get('supply')
                or state.get('balance')
                or state.get('amount')
                or 0
            )
            total += int(balance_field)

        return total

    def transfer(self, recipient_addr: str, amount: int) -> str:
        """Transfer the entire balance of a token UTXO to a new address.

        The FungibleToken.transfer(sig, to) method transfers the full supply
        held in the UTXO to the given address. The signature is produced by
        this wallet's signer and passed as the first argument.

        Args:
            recipient_addr: The BSV address (Addr) of the recipient.
            amount: Minimum token balance required in the source UTXO.

        Returns:
            The txid of the transfer transaction.

        .. deprecated::
            Unsafe (N-239): the ``transfer(sig, to: Addr)`` ABI cannot re-key a
            PubKey holder, so the token does not move to ``recipient_addr``.
            Use the token-ft example (FungibleTokenExample) instead.
        """
        warnings.warn(_TRANSFER_DEPRECATION, DeprecationWarning, stacklevel=2)
        utxos = self.get_utxos()
        if not utxos:
            raise RuntimeError('TokenWallet.transfer: no token UTXOs found')

        for utxo in utxos:
            contract = RunarContract.from_txid(
                self.artifact,
                utxo.txid,
                utxo.output_index,
                self.provider,
            )
            state = contract.get_state()
            balance = int(
                state.get('balance')
                or state.get('supply')
                or state.get('amount')
                or 0
            )

            if balance >= amount:
                # FungibleToken.transfer(sig: Sig, to: Addr)
                # F-045: pass None for the Sig so contract.call auto-signs the
                # transaction it actually builds and broadcasts.
                # An Addr is a 20-byte hash160: accept a Base58 address (as
                # documented), a raw hash160, or a public key.
                to_pkh = build_p2pkh_script(recipient_addr)[6:46]
                contract.connect(self.provider, self.signer)
                txid, _ = contract.call(
                    'transfer',
                    [None, to_pkh],
                    options=None,
                )
                return txid

        raise RuntimeError(
            f'TokenWallet.transfer: insufficient token balance for transfer of {amount}'
        )

    def merge(self) -> str:
        """Merge two token UTXOs into a single UTXO.

        FungibleToken.merge(sig, otherSupply, otherHolder) combines the supply
        from two UTXOs. The second UTXO's supply and holder are read from its
        on-chain state and passed as arguments.

        Returns:
            The txid of the merge transaction.

        .. deprecated::
            Unsafe (N-239): the ``merge(sig, otherSupply, otherHolder)`` ABI
            cannot authenticate its companion input, so a holder can inflate
            supply. Use the token-ft example (FungibleTokenExample) instead.
        """
        warnings.warn(_MERGE_DEPRECATION, DeprecationWarning, stacklevel=2)
        utxos = self.get_utxos()
        if len(utxos) < 2:
            raise RuntimeError('TokenWallet.merge: need at least 2 UTXOs to merge')

        first_utxo = utxos[0]
        contract = RunarContract.from_txid(
            self.artifact,
            first_utxo.txid,
            first_utxo.output_index,
            self.provider,
        )

        # Read the second UTXO's state to extract its supply and holder.
        second_utxo = utxos[1]
        second_contract = RunarContract.from_txid(
            self.artifact,
            second_utxo.txid,
            second_utxo.output_index,
            self.provider,
        )
        second_state = second_contract.get_state()
        other_supply = int(
            second_state.get('supply')
            or second_state.get('balance')
            or second_state.get('amount')
            or 0
        )
        other_holder = second_state.get('holder', '')

        # FungibleToken.merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey)
        # F-045: spend BOTH token UTXOs in one tx. Each input's unlock carries
        # the OTHER input's supply/holder, and every Sig is None so
        # contract.call signs each input over the tx it actually broadcasts.
        first_state = contract.get_state()
        first_supply = int(
            first_state.get('supply')
            or first_state.get('balance')
            or first_state.get('amount')
            or 0
        )
        first_holder = first_state.get('holder', '')

        contract.connect(self.provider, self.signer)
        change_address = self.signer.get_address()

        from runar.sdk.types import CallOptions
        txid, _ = contract.call(
            'merge',
            [None, other_supply, other_holder],
            options=CallOptions(
                change_address=change_address,
                additional_contract_inputs=[second_utxo],
                additional_contract_input_args=[[None, first_supply, first_holder]],
            ),
        )

        return txid

    def get_utxos(self) -> list[Utxo]:
        """Get all token UTXOs associated with this wallet's signer address.

        Filters to UTXOs whose script starts with the token contract's
        script prefix (the code portion, before state).
        """
        address = self.signer.get_address()
        all_utxos = self.provider.get_utxos(address)

        # N-076: the artifact script is the TEMPLATE; every slot (constructor
        # arg, codeSepIndex, code-part length) is a placeholder that
        # deployment replaces, so a raw prefix of it never matches a slotted
        # deployment. With constructor slots, use the slot-aware
        # ``matches_artifact``; a template with none is deployed verbatim, so
        # its literal prefix is exact.
        template = self.artifact.script
        slotted = bool(self.artifact.constructor_slots)

        result: list[Utxo] = []
        for utxo in all_utxos:
            # If we have the script, compare it with the contract code.
            # Otherwise, include all UTXOs (caller can filter further).
            if not utxo.script or not template:
                result.append(utxo)
            elif not slotted:
                if utxo.script.startswith(template):
                    result.append(utxo)
            else:
                code_hex = utxo.script
                # matches_artifact strips the state section only for
                # artifacts that declare state fields; cut it here for the rest.
                if not self.artifact.state_fields:
                    pos = find_last_op_return(code_hex)
                    if pos != -1:
                        code_hex = code_hex[:pos]
                try:
                    if matches_artifact(self.artifact, code_hex):
                        result.append(utxo)
                except MalformedScriptError:
                    # Not well-formed at the artifact's slot offsets (F-238):
                    # not an instance of this contract.
                    pass

        return result
