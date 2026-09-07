"""Cross-tier parity for the EXPERIMENTAL EC size flags.

The flags default off, so the ordinary conformance suite -- which compiles with
defaults -- cannot see them at all. Seven tiers could each ship a DIFFERENT
``--ec-constant-pool`` and the suite would stay green.

That matters because the flags are not cosmetic: they change which reduction
form is emitted and which addition formula each ladder round uses. A tier that
ports the constant pool but not the sign lattice's ``REDUCED`` precondition
produces a script that is smaller, passes its own tests, and is wrong on
``ecAdd((0,1), (2^256-1,1))``. Byte-identical output against a single reference
is the only cheap check that catches that.

``conformance/ec-flag-parity/expected.json`` is derived from the TypeScript
reference compiler and re-derived by its own vitest, so it cannot go stale.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runar_compiler.codegen import ec, p256_p384
from runar_compiler.codegen.emit import emit_method
from runar_compiler.codegen.stack import StackMethod

FIXTURE = (Path(__file__).resolve().parents[3]
           / "conformance" / "ec-flag-parity" / "expected.json")

_FIELD = {
    "constantPool": "constant_pool",
    "reductionSinking": "reduction_sinking",
    "fixedBaseComb": "fixed_base_comb",
}


def _ignore_opts(fn):
    """Adapt an emitter the flags cannot reach to the options-taking shape.

    These are deliberately included: a tier that accidentally made
    ``ecModReduce`` or ``ecPointX`` flag-sensitive would be diverging just as
    badly as one that ignored a flag.
    """
    return lambda e, _opts=None: fn(e)


EMITTERS = {
    "EcAdd": ec.emit_ec_add,
    "EcMul": ec.emit_ec_mul,
    "EcMulGen": ec.emit_ec_mul_gen,
    "EcNegate": ec.emit_ec_negate,
    "EcOnCurve": ec.emit_ec_on_curve,
    "EcModReduce": _ignore_opts(ec.emit_ec_mod_reduce),
    "EcEncodeCompressed": _ignore_opts(ec.emit_ec_encode_compressed),
    "EcMakePoint": _ignore_opts(ec.emit_ec_make_point),
    "EcPointX": _ignore_opts(ec.emit_ec_point_x),
    "EcPointY": _ignore_opts(ec.emit_ec_point_y),
    "P256Add": p256_p384.emit_p256_add,
    "P256Mul": p256_p384.emit_p256_mul,
    "P256MulGen": p256_p384.emit_p256_mul_gen,
    "P256Negate": p256_p384.emit_p256_negate,
    "P256OnCurve": p256_p384.emit_p256_on_curve,
    "P256EncodeCompressed": _ignore_opts(p256_p384.emit_p256_encode_compressed),
    "VerifyECDSA_P256": p256_p384.emit_verify_ecdsa_p256,
    "P384Add": p256_p384.emit_p384_add,
    "P384Mul": p256_p384.emit_p384_mul,
    "P384MulGen": p256_p384.emit_p384_mul_gen,
    "P384Negate": p256_p384.emit_p384_negate,
    "P384OnCurve": p256_p384.emit_p384_on_curve,
    "P384EncodeCompressed": _ignore_opts(p256_p384.emit_p384_encode_compressed),
    "VerifyECDSA_P384": p256_p384.emit_verify_ecdsa_p384,
}


def _fixture() -> dict:
    return json.loads(FIXTURE.read_text())


def _emit_and_hash(fn, opts) -> tuple[int, str]:
    ops: list = []
    fn(ops.append, opts)
    res = emit_method(StackMethod(name="t", ops=ops))
    raw = bytes.fromhex(res.script_hex)
    return len(raw), hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("name", sorted(EMITTERS))
def test_ec_flag_parity_against_typescript_reference(name: str) -> None:
    fx = _fixture()
    want = fx["emitters"][name]
    for variant, spec in fx["variants"].items():
        opts = (ec.EcCodegenOptions(**{_FIELD[k]: v for k, v in spec.items()})
                if spec else None)
        got = _emit_and_hash(EMITTERS[name], opts)
        expect = (want[variant]["bytes"], want[variant]["sha256"])
        assert got == expect, (
            f"{name} under {variant}: Python emits {got[0]} bytes, "
            f"the TypeScript reference emits {expect[0]}"
        )


@pytest.mark.parametrize("name", sorted(EMITTERS))
def test_ec_flags_default_off_is_byte_identical(name: str) -> None:
    """``None`` options must reproduce the shipping output.

    This is what keeps the existing goldens, the size baseline and every
    cross-tier hex comparison from moving while the flags are experimental.
    """
    fx = _fixture()
    none_size, none_hash = _emit_and_hash(EMITTERS[name], None)
    off_size, off_hash = _emit_and_hash(EMITTERS[name], ec.EcCodegenOptions())
    assert (none_size, none_hash) == (off_size, off_hash), \
        f"{name}: None and all-false options disagree"
    assert none_hash == fx["emitters"][name]["off"]["sha256"], \
        f"{name}: default output moved"
