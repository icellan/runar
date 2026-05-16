"""raw_script ANF node round-trip tests for the Python compiler.

Mirrors ``TestEmit_RawScriptRoundTrip`` in
``compilers/go/codegen/emit_test.go`` — verifies that the raw_script ANF
node (produced by the ``asm({...})`` intrinsic) loads, lowers to a single
opaque ``raw_bytes`` StackOp, and emits the input bytes verbatim with a
RawScriptSpan recorded.
"""

from __future__ import annotations

from runar_compiler.ir.loader import load_ir
from runar_compiler.codegen.stack import lower_to_stack
from runar_compiler.codegen.emit import emit


def test_emit_raw_script_round_trip() -> None:
    # A minimal UnsafeSmartContract `unlock` method whose body is a single
    # raw_script binding (the ANF shape produced by `asm({...})`). Bytes
    # "5152935987" = OP_1 OP_2 OP_ADD OP_3 OP_EQUAL — an arbitrary opaque
    # span the emitter must write verbatim.
    raw_hex = "5152935987"
    ir_json = (
        '{'
        '  "contractName": "Anyone",'
        '  "properties": [],'
        '  "methods": ['
        '    {'
        '      "name": "unlock",'
        '      "params": [],'
        '      "isPublic": true,'
        '      "body": ['
        '        { "name": "t0", "value": { "kind": "raw_script", '
        '          "bytes": "' + raw_hex + '", "in_arity": 0, "out_arity": 1 } }'
        '      ]'
        '    }'
        '  ]'
        '}'
    )

    program = load_ir(ir_json)

    # Round-trip the loaded JSON: in_arity 0 must survive.
    body = program.methods[0].body
    assert body[0].value.bytes == raw_hex
    assert body[0].value.in_arity == 0
    assert body[0].value.out_arity == 1

    methods = lower_to_stack(program)

    # The lowered method must contain exactly one raw_bytes op carrying the
    # decoded bytes.
    raw_ops = 0
    for m in methods:
        for op in m.ops:
            if op.op == "raw_bytes":
                raw_ops += 1
                assert op.raw_bytes is not None
                assert op.raw_bytes.hex() == raw_hex
                assert op.in_arity == 0
                assert op.out_arity == 1
    assert raw_ops == 1, f"expected exactly 1 raw_bytes op, got {raw_ops}"

    result = emit(methods)

    # The emitted hex must equal the input bytes verbatim (single-method
    # contract, no dispatch preamble).
    assert result.script_hex == raw_hex

    # A RawScriptSpan covering the whole span must be recorded.
    assert len(result.raw_script_spans) == 1
    span = result.raw_script_spans[0]
    assert span.offset == 0
    assert span.length == len(raw_hex) // 2
    assert span.in_arity == 0
    assert span.out_arity == 1
