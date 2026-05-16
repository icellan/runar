"""Runar base contract classes."""

from dataclasses import dataclass
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


class UnsafeSmartContract(SmartContract):
    """Base class for stateless Runar contracts that need the raw-script
    escape hatch (:func:`asm`).

    Like :class:`SmartContract`, all properties must be readonly --
    UnsafeSmartContract trades the type-checked subset only for the bytes
    inside ``asm()`` calls, not for mutable state. Use
    :class:`StatefulSmartContract` for mutable state.
    """

    def __init__(self, *args: Any) -> None:
        super().__init__(*args)


@dataclass
class AsmArgs:
    """Structured argument for the :func:`asm` compiler intrinsic.

    The Rúnar Python frontend intercepts ``asm(...)`` calls at parse time and
    lowers them to a ``raw_script`` ANF node; this class only exists so
    native compilation of contract source succeeds.
    """

    # Even-length hex string of raw Bitcoin Script opcode bytes to embed
    # verbatim. The compiler does not re-encode or validate the semantics of
    # these bytes -- only that the string is valid hex with an even length.
    body: str
    # Number of stack items the embedded bytes consume on entry. Defaults to 0.
    in_arity: int = 0
    # Number of stack items the embedded bytes leave on exit. Defaults to 1 so
    # the common "terminal value of a public method" case works without
    # ceremony.
    out_arity: int = 1


def asm(body: str, in_arity: int = 0, out_arity: int = 1) -> Any:
    """Embed a raw Bitcoin Script byte sequence in a contract method.

    Only callable from inside a contract extending
    :class:`UnsafeSmartContract` -- the compiler enforces this. The Python
    surface spelling is the positional form ``asm(body, in_arity, out_arity)``;
    the compiler normalises every frontend to the same ``raw_script`` ANF node.

    This runtime stub raises: ``asm`` is a compile-time intrinsic and cannot
    be executed off-chain.
    """
    raise RuntimeError(
        "asm() cannot be called at runtime -- compile this contract with "
        "the Rúnar compiler"
    )
