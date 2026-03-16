"""Main compiler pipeline orchestrator.

Reads source files or ANF IR JSON, runs the compilation pipeline, and produces
a Runar artifact. Direct port of ``compilers/go/compiler.go``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from runar_compiler.ir.types import ANFProgram


# ---------------------------------------------------------------------------
# Artifact types -- mirrors the TypeScript RunarArtifact schema
# ---------------------------------------------------------------------------

@dataclass
class ABIParam:
    """A parameter in the ABI."""

    name: str = ""
    type: str = ""


@dataclass
class ABIConstructor:
    """The constructor ABI."""

    params: list[ABIParam] = field(default_factory=list)


@dataclass
class ABIMethod:
    """A method in the ABI."""

    name: str = ""
    params: list[ABIParam] = field(default_factory=list)
    is_public: bool = False
    is_terminal: bool | None = None


@dataclass
class ABI:
    """The contract's public interface."""

    constructor: ABIConstructor = field(default_factory=ABIConstructor)
    methods: list[ABIMethod] = field(default_factory=list)


@dataclass
class StateField:
    """A stateful contract field."""

    name: str = ""
    type: str = ""
    index: int = 0
    initial_value: str | int | bool | None = None


@dataclass
class ConstructorSlot:
    """Records a constructor parameter placeholder in the compiled script."""

    param_index: int = 0
    byte_offset: int = 0


@dataclass
class Artifact:
    """The final compiled output of a Runar compiler."""

    version: str = ""
    compiler_version: str = ""
    contract_name: str = ""
    abi: ABI = field(default_factory=ABI)
    script: str = ""
    asm: str = ""
    state_fields: list[StateField] = field(default_factory=list)
    constructor_slots: list[ConstructorSlot] = field(default_factory=list)
    code_separator_index: int | None = None
    code_separator_indices: list[int] | None = None
    build_timestamp: str = ""
    anf: ANFProgram | None = None


SCHEMA_VERSION = "runar-v0.1.0"
COMPILER_VERSION = "0.1.0-python"


# ---------------------------------------------------------------------------
# Frontend stub imports (filled in as parsers are ported)
# ---------------------------------------------------------------------------

def _parse_source(source: bytes, file_name: str) -> Any:
    """Dispatch to the correct parser based on file extension.

    Returns a ParseResult-like object (from the frontend package).
    """
    lower = file_name.lower()
    if lower.endswith(".runar.py"):
        from runar_compiler.frontend.parser_python import parse_python
        return parse_python(source, file_name)
    elif lower.endswith(".runar.ts"):
        from runar_compiler.frontend.parser_ts import parse_ts
        return parse_ts(source, file_name)
    elif lower.endswith(".runar.sol"):
        from runar_compiler.frontend.parser_sol import parse_sol
        return parse_sol(source, file_name)
    elif lower.endswith(".runar.move"):
        from runar_compiler.frontend.parser_move import parse_move
        return parse_move(source, file_name)
    elif lower.endswith(".runar.go"):
        from runar_compiler.frontend.parser_go import parse_go
        return parse_go(source, file_name)
    elif lower.endswith(".runar.rs"):
        from runar_compiler.frontend.parser_rust import parse_rust
        return parse_rust(source, file_name)
    elif lower.endswith(".runar.rb"):
        from runar_compiler.frontend.parser_ruby import parse_ruby
        return parse_ruby(source, file_name)
    else:
        raise ValueError(
            f"Unsupported source format: {file_name}. "
            f"Expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, or .runar.rb"
        )


def _validate(contract: Any) -> Any:
    """Run validation on a parsed ContractNode.

    Returns a ValidationResult-like object.
    """
    from runar_compiler.frontend.validator import validate
    return validate(contract)


def _type_check(contract: Any) -> Any:
    """Run type checking on a parsed ContractNode.

    Returns a TypeCheckResult-like object.
    """
    from runar_compiler.frontend.typecheck import type_check
    return type_check(contract)


def _lower_to_anf(contract: Any) -> ANFProgram:
    """Lower a ContractNode to ANF IR."""
    from runar_compiler.frontend.anf_lower import lower_to_anf
    return lower_to_anf(contract)


# ---------------------------------------------------------------------------
# Backend stub imports
# ---------------------------------------------------------------------------

def _fold_constants(program: ANFProgram) -> ANFProgram:
    """Constant folding: evaluate compile-time-known expressions (Pass 4.25)."""
    from runar_compiler.frontend.constant_fold import fold_constants
    return fold_constants(program)


def _optimize_ec(program: ANFProgram) -> ANFProgram:
    """Optimize EC operations in ANF IR (Pass 4.5)."""
    from runar_compiler.frontend.anf_optimize import optimize_ec
    return optimize_ec(program)


def _lower_to_stack(program: ANFProgram) -> list[Any]:
    """Stack lowering: ANF -> Stack IR."""
    from runar_compiler.codegen.stack import lower_to_stack
    return lower_to_stack(program)


def _optimize_stack_ops(ops: list[Any]) -> list[Any]:
    """Peephole optimize a list of StackOps."""
    from runar_compiler.codegen.optimizer import optimize_stack_ops
    return optimize_stack_ops(ops)


def _emit(stack_methods: list[Any]) -> Any:
    """Emit Bitcoin Script from Stack IR."""
    from runar_compiler.codegen.emit import emit
    return emit(stack_methods)


def _load_ir(path: str) -> ANFProgram:
    """Load ANF IR from a JSON file."""
    from runar_compiler.ir.loader import load_ir_from_file
    return load_ir_from_file(path)


def _load_ir_from_bytes(data: bytes) -> ANFProgram:
    """Load ANF IR from raw JSON bytes."""
    from runar_compiler.ir.loader import load_ir
    return load_ir(data if isinstance(data, str) else data.decode("utf-8"))


# ---------------------------------------------------------------------------
# Compilation pipeline
# ---------------------------------------------------------------------------

def compile_from_ir(ir_path: str, disable_constant_folding: bool = False) -> Artifact:
    """Read an ANF IR JSON file and compile it to a Runar artifact."""
    program = _load_ir(ir_path)
    return compile_from_program(program, disable_constant_folding=disable_constant_folding)


def compile_from_ir_bytes(data: bytes, disable_constant_folding: bool = False) -> Artifact:
    """Compile from raw ANF IR JSON bytes."""
    program = _load_ir_from_bytes(data)
    return compile_from_program(program, disable_constant_folding=disable_constant_folding)


def compile_from_program(program: ANFProgram, disable_constant_folding: bool = False) -> Artifact:
    """Compile a parsed ANF program to a Runar artifact."""
    # Pass 4.25: Constant folding (on by default)
    if not disable_constant_folding:
        program = _fold_constants(program)

    # Pass 4.5: EC optimization
    program = _optimize_ec(program)

    # Pass 5: Stack lowering
    stack_methods = _lower_to_stack(program)

    # Peephole optimization -- runs on Stack IR before emission.
    for sm in stack_methods:
        sm.ops = _optimize_stack_ops(sm.ops)

    # Pass 6: Emit
    emit_result = _emit(stack_methods)

    return _assemble_artifact(
        program,
        emit_result.script_hex,
        emit_result.script_asm,
        emit_result.constructor_slots,
        emit_result.code_separator_index,
        emit_result.code_separator_indices,
    )


def compile_from_source(source_path: str, disable_constant_folding: bool = False) -> Artifact:
    """Compile a source file through all passes to a Runar artifact.

    Supports .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs,
    and .runar.py extensions (dispatched by file extension).
    """
    source = _read_file(source_path)

    # Pass 1: Parse
    parse_result = _parse_source(source, source_path)
    if parse_result.errors:
        raise CompilationError("parse errors:\n  " + "\n  ".join(parse_result.errors))
    if parse_result.contract is None:
        raise CompilationError(f"no contract found in {source_path}")

    # Pass 2: Validate
    valid_result = _validate(parse_result.contract)
    if valid_result.errors:
        raise CompilationError("validation errors:\n  " + "\n  ".join(valid_result.errors))

    # Pass 3: Type check
    tc_result = _type_check(parse_result.contract)
    if tc_result.errors:
        raise CompilationError("type check errors:\n  " + "\n  ".join(tc_result.errors))

    # Pass 4: ANF lowering
    program = _lower_to_anf(parse_result.contract)

    # Feed into existing compilation pipeline (passes 4.25-6)
    return compile_from_program(program, disable_constant_folding=disable_constant_folding)


def compile_source_to_ir(source_path: str, disable_constant_folding: bool = False) -> ANFProgram:
    """Run passes 1-4 on a source file and return the ANF program."""
    source = _read_file(source_path)

    parse_result = _parse_source(source, source_path)
    if parse_result.errors:
        raise CompilationError("parse errors:\n  " + "\n  ".join(parse_result.errors))
    if parse_result.contract is None:
        raise CompilationError(f"no contract found in {source_path}")

    valid_result = _validate(parse_result.contract)
    if valid_result.errors:
        raise CompilationError("validation errors:\n  " + "\n  ".join(valid_result.errors))

    tc_result = _type_check(parse_result.contract)
    if tc_result.errors:
        raise CompilationError("type check errors:\n  " + "\n  ".join(tc_result.errors))

    program = _lower_to_anf(parse_result.contract)

    # Pass 4.25: Constant folding (on by default)
    if not disable_constant_folding:
        program = _fold_constants(program)

    # Pass 4.5: EC optimization
    program = _optimize_ec(program)

    return program


# ---------------------------------------------------------------------------
# Artifact assembly
# ---------------------------------------------------------------------------

def _assemble_artifact(
    program: ANFProgram,
    script_hex: str,
    script_asm: str,
    constructor_slots: list[ConstructorSlot],
    code_separator_index: int = -1,
    code_separator_indices: list[int] | None = None,
) -> Artifact:
    """Build the final output artifact from the compilation products."""
    # Build ABI
    # Initialized properties are excluded from constructor params — they
    # get their values from the initializer, not from the caller.
    constructor_params = [
        ABIParam(name=prop.name, type=prop.type)
        for prop in program.properties
        if prop.initial_value is None
    ]

    # Build state fields for stateful contracts
    # index = position in constructor args (not sequential among state fields)
    state_fields: list[StateField] = []
    for i, prop in enumerate(program.properties):
        if not prop.readonly:
            sf = StateField(name=prop.name, type=prop.type, index=i)
            if prop.initial_value is not None:
                sf.initial_value = prop.initial_value
            state_fields.append(sf)

    is_stateful = len(state_fields) > 0

    # Build method ABIs (exclude constructor — it's in abi.constructor, not methods)
    methods: list[ABIMethod] = []
    for method in program.methods:
        if method.name == "constructor":
            continue
        params = [ABIParam(name=p.name, type=p.type) for p in method.params]
        # For stateful contracts, mark public methods without _changePKH as terminal
        is_terminal: bool | None = None
        if is_stateful and method.is_public:
            has_change = any(p.name == "_changePKH" for p in method.params)
            if not has_change:
                is_terminal = True
        methods.append(ABIMethod(
            name=method.name,
            params=params,
            is_public=method.is_public,
            is_terminal=is_terminal,
        ))

    cs_index = code_separator_index if code_separator_index >= 0 else None
    cs_indices = code_separator_indices if code_separator_indices else None

    art = Artifact(
        version=SCHEMA_VERSION,
        compiler_version=COMPILER_VERSION,
        contract_name=program.contract_name,
        abi=ABI(
            constructor=ABIConstructor(params=constructor_params),
            methods=methods,
        ),
        script=script_hex,
        asm=script_asm,
        state_fields=state_fields,
        constructor_slots=constructor_slots,
        code_separator_index=cs_index,
        code_separator_indices=cs_indices,
        build_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    # Always include ANF IR for stateful contracts — the SDK uses it
    # to auto-compute state transitions without requiring manual newState.
    if is_stateful:
        art.anf = program

    return art


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------

def artifact_to_json(artifact: Artifact) -> str:
    """Serialize an artifact to pretty-printed JSON."""
    d: dict[str, Any] = {
        "version": artifact.version,
        "compilerVersion": artifact.compiler_version,
        "contractName": artifact.contract_name,
        "abi": {
            "constructor": {
                "params": [
                    {"name": p.name, "type": p.type}
                    for p in artifact.abi.constructor.params
                ],
            },
            "methods": [
                {
                    "name": m.name,
                    "params": [{"name": p.name, "type": p.type} for p in m.params],
                    "isPublic": m.is_public,
                    **({"isTerminal": m.is_terminal} if m.is_terminal is not None else {}),
                }
                for m in artifact.abi.methods
            ],
        },
        "script": artifact.script,
        "asm": artifact.asm,
    }
    if artifact.state_fields:
        d["stateFields"] = [
            {
                "name": sf.name, "type": sf.type, "index": sf.index,
                **({"initialValue": sf.initial_value} if sf.initial_value is not None else {}),
            }
            for sf in artifact.state_fields
        ]
    if artifact.constructor_slots:
        d["constructorSlots"] = [
            {"paramIndex": cs.param_index, "byteOffset": cs.byte_offset}
            for cs in artifact.constructor_slots
        ]
    if artifact.code_separator_index is not None:
        d["codeSeparatorIndex"] = artifact.code_separator_index
    if artifact.code_separator_indices is not None:
        d["codeSeparatorIndices"] = artifact.code_separator_indices
    d["buildTimestamp"] = artifact.build_timestamp
    if artifact.anf is not None:
        d["anf"] = _serialize_anf_program(artifact.anf)
    return json.dumps(d, indent=2)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_anf_program(program: ANFProgram) -> dict[str, Any]:
    """Serialize an ANFProgram to a JSON-compatible dict (camelCase keys)."""
    def _ser_value(v: Any) -> dict[str, Any]:
        """Serialize an ANFValue to a dict."""
        d: dict[str, Any] = {"kind": v.kind}
        if v.name is not None:
            d["name"] = v.name
        if v.raw_value is not None:
            # raw_value is already JSON-ready (string, number, bool)
            d["value"] = json.loads(v.raw_value) if isinstance(v.raw_value, str) else v.raw_value
        if v.op is not None:
            d["op"] = v.op
        if v.left is not None:
            d["left"] = v.left
        if v.right is not None:
            d["right"] = v.right
        if v.result_type is not None:
            d["result_type"] = v.result_type
        if v.operand is not None:
            d["operand"] = v.operand
        if v.func is not None:
            d["func"] = v.func
        if v.args is not None:
            d["args"] = v.args
        if v.object is not None:
            d["object"] = v.object
        if v.method is not None:
            d["method"] = v.method
        if v.cond is not None:
            d["cond"] = v.cond
        if v.then is not None:
            d["then"] = [_ser_binding(b) for b in v.then]
        if v.else_ is not None:
            d["else"] = [_ser_binding(b) for b in v.else_]
        if v.count is not None:
            d["count"] = v.count
        if v.iter_var is not None:
            d["iterVar"] = v.iter_var
        if v.body is not None:
            d["body"] = [_ser_binding(b) for b in v.body]
        if v.value_ref is not None:
            d["value"] = v.value_ref
        if v.preimage is not None:
            d["preimage"] = v.preimage
        if v.satoshis is not None:
            d["satoshis"] = v.satoshis
        if v.state_values is not None:
            d["stateValues"] = v.state_values
        if v.script_bytes is not None:
            d["scriptBytes"] = v.script_bytes
        return d

    def _ser_binding(b: Any) -> dict[str, Any]:
        return {"name": b.name, "value": _ser_value(b.value)}

    return {
        "contractName": program.contract_name,
        "properties": [
            {
                "name": p.name,
                "type": p.type,
                "readonly": p.readonly,
                **({"initialValue": p.initial_value} if p.initial_value is not None else {}),
            }
            for p in program.properties
        ],
        "methods": [
            {
                "name": m.name,
                "params": [{"name": p.name, "type": p.type} for p in m.params],
                "body": [_ser_binding(b) for b in m.body],
                "isPublic": m.is_public,
            }
            for m in program.methods
        ],
    }


class CompilationError(Exception):
    """Raised when any compiler pass produces errors."""


def _read_file(path: str) -> str:
    """Read a file as text."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
