"""Runar base contract classes."""

from typing import Any


class SmartContract:
    """Base class for stateless Runar smart contracts.

    All properties are readonly. The contract logic is pure — no state
    is carried between spending transactions.
    """

    def __init__(self, *args: Any) -> None:
        pass


class StatefulSmartContract(SmartContract):
    """Base class for stateful Runar smart contracts.

    Mutable properties are carried in the UTXO state. The compiler
    auto-injects checkPreimage at method entry and state continuation
    at exit.
    """

    tx_preimage: bytes = b''
    _outputs: list

    def __init__(self, *args: Any) -> None:
        super().__init__(*args)
        self._outputs = []

    def add_output(self, satoshis: int, *state_values: Any) -> None:
        """Add an output with the given satoshis and state values."""
        self._outputs.append({"satoshis": satoshis, "values": list(state_values)})

    def get_state_script(self) -> bytes:
        """Get the state script for the current contract state."""
        return b''

    def reset_outputs(self) -> None:
        """Reset the outputs list."""
        self._outputs = []
