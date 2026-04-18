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
        self._outputs.append({
            "kind": "state",
            "satoshis": satoshis,
            "values": list(state_values),
        })

    def add_raw_output(self, satoshis: int, script_bytes: bytes) -> None:
        """Add a raw output with caller-specified script bytes. Not included
        in the continuation state — the script is used as-is."""
        self._outputs.append({
            "kind": "raw",
            "satoshis": satoshis,
            "script_bytes": script_bytes,
        })

    def add_data_output(self, satoshis: int, script_bytes: bytes) -> None:
        """Add an arbitrary-script output alongside state continuation.

        Like :meth:`add_raw_output` in wire shape, but these outputs are
        included in the auto-computed continuation hash (``hashOutputs``)
        in declaration order, after state outputs and before the change
        output. Distinguished at the Python level by the ``kind`` field so
        tests can tell state vs data outputs apart.
        """
        self._outputs.append({
            "kind": "data",
            "satoshis": satoshis,
            "script_bytes": script_bytes,
        })

    def get_state_script(self) -> bytes:
        """Get the state script for the current contract state."""
        return b''

    def reset_outputs(self) -> None:
        """Reset the outputs list."""
        self._outputs = []
