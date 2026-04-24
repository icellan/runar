"""Tests for the full state-property type allowlist in `deserialize_state`.

The validator accepts 14 property types (bigint, boolean, ByteString, PubKey,
Sig, Sha256, Ripemd160, Addr, SigHashPreimage, RabinSig, RabinPubKey, Point,
P256Point, P384Point), but historically the codegen allowlist in
`_lower_deserialize_state` only covered 7 of them and panicked with
``deserialize_state: unsupported type: <T>`` for Sig, Ripemd160,
SigHashPreimage, RabinSig, RabinPubKey, P256Point, and P384Point when used as
state fields.

This file mirrors the Rust fix (commit e879e58, see
compilers/rust/tests/compiler_tests.rs `test_deserialize_state_ripemd160_codegens_cleanly`)
by verifying that each missing type now codegens cleanly when used as the sole
mutable state property on a stateful contract.

Tests build a minimal `ANFProgram` with a single mutable state property, a
stateful entry method that performs a `deserialize_state` followed by an
update, and then run the stack-lowering pass directly.  Prior to the fix each
of these tests panics with ``deserialize_state: unsupported type``.
"""

from __future__ import annotations

import pytest

from runar_compiler.ir.types import (
    ANFBinding,
    ANFMethod,
    ANFParam,
    ANFProgram,
    ANFProperty,
    ANFValue,
)
from runar_compiler.codegen.stack import lower_to_stack


def _stateful_program(prop_type: str, param_type: str | None = None) -> ANFProgram:
    """Build a minimal stateful program with a single mutable property of
    *prop_type* and a public ``update`` method that deserializes state and
    reassigns the property from the given parameter.

    The `_preimage` synthetic param is how stateful entry methods receive the
    BIP-143 preimage that `deserialize_state` consumes.
    """
    if param_type is None:
        param_type = prop_type

    return ANFProgram(
        contract_name="T",
        properties=[ANFProperty(name="field", type=prop_type, readonly=False)],
        methods=[
            ANFMethod(
                name="constructor",
                params=[ANFParam(name="field", type=prop_type)],
                body=[],
                is_public=False,
            ),
            ANFMethod(
                name="update",
                params=[
                    ANFParam(name="newField", type=param_type),
                    ANFParam(name="_preimage", type="SigHashPreimage"),
                ],
                body=[
                    # Deserialize state from the preimage's scriptCode.
                    ANFBinding(
                        name="t0",
                        value=ANFValue(kind="deserialize_state", preimage="_preimage"),
                    ),
                    # Overwrite the state property from the call parameter.
                    ANFBinding(
                        name="t1",
                        value=ANFValue(kind="load_param", name="newField"),
                    ),
                    ANFBinding(
                        name="t2",
                        value=ANFValue(
                            kind="update_prop",
                            name="field",
                            raw_value="t1",
                            value_ref="t1",
                        ),
                    ),
                ],
                is_public=True,
            ),
        ],
    )


@pytest.mark.parametrize(
    "prop_type",
    [
        "Ripemd160",
        "P256Point",
        "P384Point",
        "RabinSig",
        "RabinPubKey",
        "Sig",
        "SigHashPreimage",
    ],
)
def test_deserialize_state_supports_all_validator_types(prop_type: str) -> None:
    """Every validator-accepted state-property type must codegen cleanly.

    Before the fix, `_lower_deserialize_state` raises
    ``RuntimeError: deserialize_state: unsupported type: <prop_type>`` for each
    of these types.
    """
    program = _stateful_program(prop_type)
    methods = lower_to_stack(program)
    assert any(m.name == "update" for m in methods), (
        f"expected an `update` stack method for prop_type={prop_type}"
    )
