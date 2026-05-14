"""Bitcoin Script virtual machine for off-chain testing and debugging.

Thin wrapper around the bsv-blockchain ``bsv-sdk`` ``Spend`` script
interpreter (``bsv.script.spend.Spend``). It does NOT re-implement Bitcoin
Script — the upstream interpreter does all execution. The wrapper drives
``Spend.step()`` and records a per-opcode trace so it can expose the same
step-mode debugger API as the TypeScript and Go ScriptVMs::

    vm = ScriptVM()
    res = vm.execute_hex("5253935587")          # one-shot execution
    vm.load_hex("", "5253935587")               # step-mode: load...
    while (step := vm.step()) is not None: ...   # ...then walk opcodes

``bsv-sdk`` is an **optional** dependency — ``runar-py`` itself has zero
required dependencies. Install the ScriptVM extra to use this module::

    pip install runar[script-vm]

If ``bsv-sdk`` is not installed, importing this module still succeeds; the
``ImportError`` is raised only when a ``ScriptVM`` method is actually
called, with a message pointing at the extra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

_BSV_IMPORT_HINT = (
    "runar.sdk.script_vm requires the optional 'bsv-sdk' dependency. "
    "Install it with:  pip install runar[script-vm]  (or: pip install bsv-sdk)"
)


def _require_bsv():
    """Lazily import bsv-sdk, raising a helpful error if it is absent."""
    try:
        from bsv.script.script import Script
        from bsv.script.spend import Spend
        from bsv.constants import OPCODE_VALUE_NAME_DICT
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(_BSV_IMPORT_HINT) from exc
    return Script, Spend, OPCODE_VALUE_NAME_DICT


@dataclass
class VMOptions:
    """Configuration for a :class:`ScriptVM`. The default is a usable VM."""

    # Reserved for future flags; kept so the constructor signature is stable
    # across tiers. bsv-sdk's Spend has no per-instance flag surface.
    pass


@dataclass
class VMResult:
    """The outcome of a full script execution."""

    success: bool
    stack: list[bytes] = field(default_factory=list)
    alt_stack: list[bytes] = field(default_factory=list)
    error: Optional[str] = None
    ops_executed: int = 0


@dataclass
class StepResult:
    """The outcome of executing a single opcode in step mode."""

    offset: int
    opcode: str
    main_stack: list[bytes] = field(default_factory=list)
    alt_stack: list[bytes] = field(default_factory=list)
    error: Optional[str] = None
    context: str = ""  # "unlocking" or "locking"


def _opcode_name(op: bytes, names: dict) -> str:
    """Resolve an opcode byte to a name. Direct-push chunks (0x01..0x4b)
    are not in the name table — report them as ``PUSH_<n>``."""
    name = names.get(op)
    if name is not None:
        return name
    if len(op) == 1 and 0x01 <= op[0] <= 0x4B:
        return f"PUSH_{op[0]}"
    return f"OP_UNKNOWN_0x{op.hex()}"


class ScriptVM:
    """Executes Bitcoin Script bytes via the bsv-sdk ``Spend`` interpreter
    and records a step trace for debugger-style inspection."""

    def __init__(self, options: Optional[VMOptions] = None) -> None:
        self._options = options or VMOptions()
        self._trace: list[StepResult] = []
        self._result: Optional[VMResult] = None
        self._pc = 0
        self._loaded = False

    # ------------------------------------------------------------------
    # One-shot execution
    # ------------------------------------------------------------------

    def execute(self, unlocking: bytes, locking: bytes) -> VMResult:
        """Run the unlocking script followed by the locking script and
        return the final VM state. An empty unlocking script is allowed."""
        trace, result = self._run(unlocking, locking)
        self._trace = trace
        self._result = result
        self._pc = 0
        self._loaded = True
        return result

    def execute_hex(self, script_hex: str) -> VMResult:
        """Run a single hex-encoded script (as the locking script, with an
        empty unlocking script) and return the final VM state."""
        return self.execute(b"", bytes.fromhex(script_hex))

    # ------------------------------------------------------------------
    # Step mode (debugger API)
    # ------------------------------------------------------------------

    def load(self, unlocking: bytes, locking: bytes) -> None:
        """Prepare the VM to step through the unlocking + locking scripts.
        The interpreter runs the scripts immediately; :meth:`step` then walks
        the recorded trace one opcode at a time."""
        trace, result = self._run(unlocking, locking)
        self._trace = trace
        self._result = result
        self._pc = 0
        self._loaded = True

    def load_hex(self, unlocking_hex: str, locking_hex: str) -> None:
        """Prepare the VM to step through hex-encoded unlocking + locking
        scripts."""
        self.load(bytes.fromhex(unlocking_hex), bytes.fromhex(locking_hex))

    def step(self) -> Optional[StepResult]:
        """Execute the next opcode and return its :class:`StepResult`, or
        ``None`` when the script has finished (or nothing is loaded)."""
        if not self._loaded or self._pc >= len(self._trace):
            return None
        step = self._trace[self._pc]
        self._pc += 1
        return step

    @property
    def pc(self) -> int:
        """The current step cursor (opcodes stepped so far)."""
        return self._pc

    @property
    def is_complete(self) -> bool:
        """Whether stepping has reached the end of the trace."""
        return self._loaded and self._pc >= len(self._trace)

    @property
    def is_success(self) -> bool:
        """Whether the loaded script executed successfully."""
        return self._result is not None and self._result.success

    @property
    def current_stack(self) -> list[bytes]:
        """The main stack after the last stepped opcode (or the final stack
        once stepping is complete / after a one-shot ``execute``)."""
        if 0 < self._pc <= len(self._trace):
            return self._trace[self._pc - 1].main_stack
        if self._result is not None:
            return self._result.stack
        return []

    @property
    def current_alt_stack(self) -> list[bytes]:
        """The alt stack at the current cursor, mirroring ``current_stack``."""
        if 0 < self._pc <= len(self._trace):
            return self._trace[self._pc - 1].alt_stack
        if self._result is not None:
            return self._result.alt_stack
        return []

    @property
    def context(self) -> str:
        """``"unlocking"`` or ``"locking"`` — which script the cursor is in."""
        if 0 < self._pc <= len(self._trace):
            return self._trace[self._pc - 1].context
        return ""

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _run(self, unlocking: bytes, locking: bytes) -> tuple[list[StepResult], VMResult]:
        Script, Spend, names = _require_bsv()

        spend = Spend({
            "sourceTXID": "00" * 32,
            "sourceOutputIndex": 0,
            "sourceSatoshis": 0,
            "lockingScript": Script(locking),
            "transactionVersion": 1,
            "otherInputs": [],
            "outputs": [],
            "inputIndex": 0,
            "unlockingScript": Script(unlocking),
            "inputSequence": 0xFFFFFFFF,
            "lockTime": 0,
        })

        trace: list[StepResult] = []
        error: Optional[str] = None

        def _ctx_label() -> str:
            return "unlocking" if spend.context == "UnlockingScript" else "locking"

        def _at_end() -> bool:
            return (
                spend.context == "LockingScript"
                and spend.program_counter >= len(spend.locking_script.chunks)
            )

        # Drive Spend.step() one opcode at a time, snapshotting state after
        # each. Spend.step() auto-transitions UnlockingScript -> LockingScript.
        try:
            while not _at_end():
                # Resolve the chunk about to run (handle the auto-transition
                # Spend.step() performs internally at the unlocking-script end).
                if (
                    spend.context == "UnlockingScript"
                    and spend.program_counter >= len(spend.unlocking_script.chunks)
                ):
                    spend.context = "LockingScript"
                    spend.program_counter = 0
                    continue
                if spend.context == "UnlockingScript":
                    chunk = spend.unlocking_script.chunks[spend.program_counter]
                else:
                    chunk = spend.locking_script.chunks[spend.program_counter]

                offset = spend.program_counter
                ctx_label = _ctx_label()
                spend.step()
                trace.append(StepResult(
                    offset=offset,
                    opcode=_opcode_name(chunk.op, names),
                    main_stack=list(spend.stack),
                    alt_stack=list(spend.alt_stack),
                    context=ctx_label,
                ))
        except Exception as exc:  # noqa: BLE001 - upstream raises bare Exception
            error = str(exc)
            if trace:
                trace[-1].error = error

        # Determine success. bsv-sdk's Spend.validate() raises on any
        # failure; here we replicate its final checks without re-running.
        success = False
        if error is None:
            balanced = len(spend.if_stack) == 0
            non_empty = len(spend.stack) > 0
            if balanced and non_empty:
                success = Spend.cast_to_bool(spend.stack[-1])
            if not success and error is None:
                # Mirror Spend.validate()'s diagnostic for a clean falsy result.
                error = "script evaluated to false (top stack element not truthy)"

        result = VMResult(
            success=success,
            stack=list(spend.stack),
            alt_stack=list(spend.alt_stack),
            error=error if not success else None,
            ops_executed=len(trace),
        )
        return trace, result
