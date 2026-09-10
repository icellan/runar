"""N-028 — an EC scalar-fusing rewrite must emit its folded constant as a real binding.

The EC optimizer (pass 4.5) rewrites ``ecAdd(ecMulGen(k1), ecMulGen(k2))`` into
``ecMulGen(k1 + k2 mod n)``. The folded scalar is a *new* value, so it needs a
binding of its own in the method body — the rewritten call references it by
name and stack lowering walks the body linearly.

The Python optimizer used to register that constant only in the optimizer's
internal value map, never in the body, so every contract in which a fusing rule
fired died in stack lowering with::

    Compilation error: value '__ec_opt_1' not found on stack

Both the Go engine (``buildOpHelper`` in
``compilers/go/frontend/ec_rules_engine.go``) and the TypeScript optimizer
(``packages/runar-compiler/src/optimizer/anf-ec.ts``) insert the helper binding
immediately before the rewritten binding. Python must do the same, and must
emit the same script bytes.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from runar_compiler.frontend.anf_optimize import optimize_ec, CURVE_N
from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFProgram,
    ANFValue,
)

HERE = Path(__file__).resolve().parent
PYTHON_COMPILER_DIR = HERE.parent

# ---------------------------------------------------------------------------
# Cross-tier reference bytes
# ---------------------------------------------------------------------------
#
# Both hashes below are the SHA-256 of the lowercase script hex (no trailing
# newline) produced by the Go and TypeScript compilers for the sources in this
# file, with constant folding at its default setting. Regenerate with:
#
#   cd compilers/go && go run . --source <src> --hex | tr -d '\n' | shasum -a 256
#
# EC_LINEAR is the contract that arms the ec-mulgen-linear fusing rule.
EC_LINEAR_SOURCE = """\
import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

class ECLinear extends SmartContract {
    constructor() {
        super();
    }

    public spend(a: bigint, b: bigint) {
        assert(ecOnCurve(ecAdd(ecMulGen(5n), ecMulGen(7n))));
    }
}
"""
EC_LINEAR_REFERENCE_SHA256 = (
    "efcff80d2f183358a0a9803fff7766a65c36de6d4db22e72a68db46d2efefcf7"
)
EC_LINEAR_REFERENCE_HEX_LEN = 2548856

# Control: no EC calls at all, so `optimize_ec` returns early. Pinned so the
# fix above cannot be "achieved" by disabling the optimizer.
NO_EC_SOURCE = """\
import { SmartContract, assert } from 'runar-lang';

class NoEC extends SmartContract {
    constructor() {
        super();
    }

    public spend(a: bigint, b: bigint) {
        assert(a + b == 42n);
    }
}
"""
NO_EC_REFERENCE_HEX = "93012a9c"


def _compile_hex(tmp_path: Path, file_name: str, source: str) -> str:
    src = tmp_path / file_name
    src.write_text(source, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--source", str(src), "--hex"],
        cwd=str(PYTHON_COMPILER_DIR),
        capture_output=True,
        text=True,
        timeout=300,
        env=os.environ.copy(),
    )
    assert proc.returncode == 0, (
        f"python compiler exited {proc.returncode}\n"
        f"stdout: {proc.stdout[:400]}\nstderr: {proc.stderr[:2000]}"
    )
    out = proc.stdout.strip()
    assert "error" not in out.lower(), f"compiler reported an error: {out[:400]}"
    return out


# ---------------------------------------------------------------------------
# Unit level: the folded scalar is a real binding in the body
# ---------------------------------------------------------------------------

def _load_const_int(name: str, n: int) -> ANFBinding:
    return ANFBinding(
        name=name,
        value=ANFValue(kind="load_const", const_big_int=n, const_int=n, raw_value=n),
    )


def _call(name: str, func: str, args: list[str]) -> ANFBinding:
    return ANFBinding(name=name, value=ANFValue(kind="call", func=func, args=args))


def test_fused_scalar_is_bound_in_the_method_body():
    """ecAdd(ecMulGen(5), ecMulGen(7)) -> ecMulGen(12) with 12 bound in the body."""
    program = ANFProgram(
        contract_name="Test",
        properties=[],
        methods=[
            ANFMethod(
                name="test",
                params=[],
                is_public=True,
                body=[
                    _load_const_int("t0", 5),
                    _call("t1", "ecMulGen", ["t0"]),
                    _load_const_int("t2", 7),
                    _call("t3", "ecMulGen", ["t2"]),
                    _call("t4", "ecAdd", ["t1", "t3"]),
                    _call("t5", "assert", ["t4"]),
                ],
            ),
        ],
    )
    body = optimize_ec(program).methods[0].body
    names = [b.name for b in body]

    t4 = next(b for b in body if b.name == "t4")
    assert t4.value.kind == "call" and t4.value.func == "ecMulGen", (
        f"expected t4 to be rewritten to ecMulGen, got {t4.value.kind}/{t4.value.func}"
    )
    scalar_name = t4.value.args[0]

    assert scalar_name in names, (
        f"folded scalar {scalar_name!r} is referenced by t4 but has no binding in "
        f"the method body: {names}"
    )
    scalar = next(b for b in body if b.name == scalar_name)
    assert scalar.value.kind == "load_const", (
        f"expected {scalar_name} to be a load_const, got {scalar.value.kind}"
    )
    assert scalar.value.const_big_int == (5 + 7) % CURVE_N, (
        f"expected {scalar_name} = 12, got {scalar.value.const_big_int}"
    )
    assert names.index(scalar_name) < names.index("t4"), (
        f"folded scalar {scalar_name!r} must be bound before the binding that "
        f"references it: {names}"
    )


# ---------------------------------------------------------------------------
# End to end: the contract compiles, and to the same bytes as Go / TypeScript
# ---------------------------------------------------------------------------

def test_ec_fusing_contract_compiles(tmp_path):
    """A contract where an EC fusing rule fires must compile to script hex."""
    hex_out = _compile_hex(tmp_path, "ECLinear.runar.ts", EC_LINEAR_SOURCE)
    assert len(hex_out) == EC_LINEAR_REFERENCE_HEX_LEN, (
        f"expected {EC_LINEAR_REFERENCE_HEX_LEN} hex chars, got {len(hex_out)}"
    )


def test_ec_fusing_hex_matches_go_and_ts_reference(tmp_path):
    """The emitted bytes must be identical to the Go / TypeScript reference."""
    hex_out = _compile_hex(tmp_path, "ECLinear.runar.ts", EC_LINEAR_SOURCE)
    digest = hashlib.sha256(hex_out.encode("ascii")).hexdigest()
    assert digest == EC_LINEAR_REFERENCE_SHA256, (
        "Python script hex diverges from the Go/TS reference for ECLinear "
        f"(got sha256={digest}, len={len(hex_out)}; "
        f"want sha256={EC_LINEAR_REFERENCE_SHA256}, len={EC_LINEAR_REFERENCE_HEX_LEN})"
    )


def test_non_ec_contract_bytes_unchanged(tmp_path):
    """Control: a contract with no EC calls still compiles to the same bytes.

    Guards against "fixing" the EC optimizer by neutering it.
    """
    hex_out = _compile_hex(tmp_path, "NoEC.runar.ts", NO_EC_SOURCE)
    assert hex_out == NO_EC_REFERENCE_HEX, (
        f"non-EC control script changed: got {hex_out}, want {NO_EC_REFERENCE_HEX}"
    )


# ---------------------------------------------------------------------------
# The folded constant must survive the IR JSON round-trip
# ---------------------------------------------------------------------------

# A folded scalar is a value mod n, so it is routinely far beyond
# Number.MAX_SAFE_INTEGER. `bigint_json_value` is the tier's canonical encoding
# for exactly that case: bare JSON number when a double carries it losslessly,
# else the decimal digits with the JS BigInt `n` suffix, as a string.
EC_BIG_SOURCE = """\
import { SmartContract, assert, ecAdd, ecMulGen, ecOnCurve } from 'runar-lang';

class ECBig extends SmartContract {
    constructor() {
        super();
    }

    public spend(a: bigint, b: bigint) {
        assert(ecOnCurve(ecAdd(ecMulGen(123456789012345678901234567890n), ecMulGen(7n))));
    }
}
"""


def test_folded_scalar_uses_canonical_bigint_json_encoding(tmp_path):
    """A folded scalar above 2**53 must not be emitted as a bare JSON number.

    A bare number is read as an IEEE-754 double by every JS consumer (and by
    Go's encoding/json into interface{}), so an unquoted 96-bit scalar loses
    precision the moment the IR crosses a tier boundary.
    """
    src = tmp_path / "ECBig.runar.ts"
    src.write_text(EC_BIG_SOURCE, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "runar_compiler", "--source", str(src), "--emit-ir"],
        cwd=str(PYTHON_COMPILER_DIR),
        capture_output=True,
        text=True,
        timeout=300,
        env=os.environ.copy(),
    )
    assert proc.returncode == 0, f"--emit-ir failed: {proc.stderr[:2000]}"

    import json as _json

    ir = _json.loads(proc.stdout)
    folded = [
        b
        for m in ir["methods"]
        for b in m["body"]
        if b["name"].startswith("__ec_opt_")
    ]
    assert folded, "expected the EC optimizer to emit a folded-scalar binding"
    value = folded[0]["value"]["value"]
    assert value == "123456789012345678901234567897n", (
        f"folded scalar emitted as {value!r} ({type(value).__name__}); expected the "
        "canonical BigInt spelling '123456789012345678901234567897n'"
    )
