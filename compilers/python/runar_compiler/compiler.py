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
    build_timestamp: str = ""


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
    else:
        raise ValueError(
            f"Unsupported source format: {file_name}. "
            f"Expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, or .runar.py"
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

def compile_from_ir(ir_path: str) -> Artifact:
    """Read an ANF IR JSON file and compile it to a Runar artifact."""
    program = _load_ir(ir_path)
    return compile_from_program(program)


def compile_from_ir_bytes(data: bytes) -> Artifact:
    """Compile from raw ANF IR JSON bytes."""
    program = _load_ir_from_bytes(data)
    return compile_from_program(program)


def compile_from_program(program: ANFProgram) -> Artifact:
    """Compile a parsed ANF program to a Runar artifact."""
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
    )


def compile_from_source(source_path: str) -> Artifact:
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

    # Pass 4.5: EC optimization
    program = _optimize_ec(program)

    # Feed into existing compilation pipeline (passes 5-6)
    return compile_from_program(program)


def compile_source_to_ir(source_path: str) -> ANFProgram:
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
) -> Artifact:
    """Build the final output artifact from the compilation products."""
    # Build ABI
    constructor_params = [
        ABIParam(name=prop.name, type=prop.type)
        for prop in program.properties
    ]

    methods = [
        ABIMethod(
            name=method.name,
            params=[ABIParam(name=p.name, type=p.type) for p in method.params],
            is_public=method.is_public,
        )
        for method in program.methods
    ]

    # Build state fields for stateful contracts
    # index = position in constructor args (not sequential among state fields)
    state_fields: list[StateField] = []
    for i, prop in enumerate(program.properties):
        if not prop.readonly:
            state_fields.append(StateField(name=prop.name, type=prop.type, index=i))

    return Artifact(
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
        build_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


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
                }
                for m in artifact.abi.methods
            ],
        },
        "script": artifact.script,
        "asm": artifact.asm,
    }
    if artifact.state_fields:
        d["stateFields"] = [
            {"name": sf.name, "type": sf.type, "index": sf.index}
            for sf in artifact.state_fields
        ]
    if artifact.constructor_slots:
        d["constructorSlots"] = [
            {"paramIndex": cs.param_index, "byteOffset": cs.byte_offset}
            for cs in artifact.constructor_slots
        ]
    d["buildTimestamp"] = artifact.build_timestamp
    return json.dumps(d, indent=2)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class CompilationError(Exception):
    """Raised when any compiler pass produces errors."""


def _read_file(path: str) -> str:
    """Read a file as text."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
