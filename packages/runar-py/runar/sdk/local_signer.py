"""LocalSigner — private key in memory, uses bsv-sdk for real ECDSA signing.

Requires the `bsv-sdk` package to be installed:
    pip install bsv-sdk

If bsv-sdk is not available, importing this module will succeed but
constructing a LocalSigner will raise RuntimeError.
"""

from __future__ import annotations

import hashlib

from runar.sdk.signer import Signer

try:
    from bsv import PrivateKey, PublicKey, Transaction as BsvTransaction  # type: ignore
    from bsv import P2PKH, Script, TransactionInput, TransactionOutput  # type: ignore
    from bsv.constants import SIGHASH  # type: ignore
    _BSV_SDK_AVAILABLE = True
except ImportError:
    _BSV_SDK_AVAILABLE = False


class LocalSigner(Signer):
    """Holds a private key in memory for signing transactions.

    Suitable for CLI tooling and testing. For production wallets, use
    ExternalSigner with hardware wallet callbacks instead.

    Requires the bsv-sdk package (``pip install bsv-sdk``).
    """

    def __init__(self, key_hex: str):
        """Create a LocalSigner from a 64-char hex private key."""
        if not _BSV_SDK_AVAILABLE:
            raise RuntimeError(
                'LocalSigner requires the bsv-sdk package. '
                'Install it with: pip install bsv-sdk'
            )
        self._priv_key = PrivateKey(bytes.fromhex(key_hex))
        self._pub_key = self._priv_key.public_key()

    def get_public_key(self) -> str:
        return self._pub_key.hex()

    def get_address(self) -> str:
        return self._pub_key.address()

    def sign(
        self,
        tx_hex: str,
        input_index: int,
        subscript: str,
        satoshis: int,
        sighash_type: int | None = None,
    ) -> str:
        """Sign a transaction input using BIP-143 sighash and ECDSA.

        Returns the DER-encoded signature with sighash byte, hex-encoded.
        """
        flag = sighash_type if sighash_type is not None else 0x41  # ALL|FORKID

        tx = BsvTransaction.from_hex(tx_hex)

        # Set the source output info needed for BIP-143 sighash computation.
        # Create a dummy source transaction with the right output at the right index.
        source_output_index = tx.inputs[input_index].source_output_index
        source_tx = BsvTransaction()
        # Pad with empty outputs up to the source index
        for _ in range(source_output_index):
            source_tx.add_output(TransactionOutput(locking_script=Script(), satoshis=0))
        locking_script = Script(bytes.fromhex(subscript))
        source_tx.add_output(TransactionOutput(
            locking_script=locking_script,
            satoshis=satoshis,
        ))
        tx.inputs[input_index].source_transaction = source_tx

        # Set the unlocking script template so sign() knows how to sign this input
        tx.inputs[input_index].unlocking_script_template = P2PKH().unlock(self._priv_key)

        # Set locking script and satoshis for BIP-143 sighash preimage computation
        tx.inputs[input_index].locking_script = locking_script
        tx.inputs[input_index].satoshis = satoshis

        # Clear existing unlocking script so sign() processes this input
        tx.inputs[input_index].unlocking_script = None

        # Sign the full transaction — this fills in unlocking scripts
        tx.sign()

        # Extract the signature from the signed unlocking script.
        # P2PKH unlocking script: <sig> <pubkey>
        # The signature is the first push data element.
        unlocking_hex = tx.inputs[input_index].unlocking_script.hex()
        sig_hex = _extract_first_push(unlocking_hex)
        return sig_hex


def _extract_first_push(script_hex: str) -> str:
    """Extract the first push data element from a script hex string."""
    data = bytes.fromhex(script_hex)
    if not data:
        raise ValueError("empty script")
    opcode = data[0]
    if 1 <= opcode <= 75:
        # Direct push: opcode is the length
        return data[1:1 + opcode].hex()
    elif opcode == 0x4c:  # OP_PUSHDATA1
        length = data[1]
        return data[2:2 + length].hex()
    elif opcode == 0x4d:  # OP_PUSHDATA2
        length = int.from_bytes(data[1:3], 'little')
        return data[3:3 + length].hex()
    else:
        raise ValueError(f"unexpected opcode 0x{opcode:02x} at start of script")
