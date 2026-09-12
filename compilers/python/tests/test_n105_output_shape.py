"""N-105 (2/2) -- the rest of TypeScript's output-intrinsic CONTRACT: the
StatefulSmartContract gate, the arity of all three intrinsics, and the types of
addOutput's state values.

N-098 ported the satoshis check and N-105 (1/2) the scriptBytes check. These
three are the remainder, and each was a hole with an executed consequence in
this tier::

    this.addOutput(1000n)                  1352 hexchars -- the state value is
      with one mutable property            simply MISSING from the continuation;
                                           the correct call emits 1362.
    this.addOutput(1000n, this.count, 5n)  1368 hexchars -- the surplus value is
                                           appended to a state serialization the
                                           next spend deserializes by fixed
                                           offsets.
    this.addOutput(1000n, this.blob)       1362 hexchars, DIFFERENT bytes -- the
      with count: bigint                   ByteString is serialized where an
                                           8-byte LE number belongs.
    this.addRawOutput(...) in a            152 hexchars -- a "continuation" in a
      stateless SmartContract              contract that has no state.

All four are the same class as N-098: the compiler does not refuse, it emits a
covenant that commits to the wrong thing.

Ported from the TypeScript reference, wording included.

The ACCEPT block is where the risk is. A ByteString-typed value in a
PubKey-typed state slot must stay ACCEPTED: ``is_subtype`` treats the ByteString
family as bidirectionally compatible. N-104: it did not always -- this module
carried a private ``_output_state_value_matches`` so the state-value check alone
got the reference tier's rule while every other check got a narrower one.
``is_subtype`` is the reference's now, and the helper is gone.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

HEAD = """import { StatefulSmartContract, ByteString, PubKey, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  owner: PubKey;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, owner: PubKey, base: bigint, blob: ByteString) {
    super(count, owner, base, blob);
    this.count = count;
    this.owner = owner;
    this.base = base;
    this.blob = blob;
  }

  private anything(): bigint { return this.base; }

"""

STATELESS_HEAD = """import { SmartContract, ByteString, assert } from 'runar-lang';

class C extends SmartContract {
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(base: bigint, blob: ByteString) {
    super(base, blob);
    this.base = base;
    this.blob = blob;
  }

"""


def stateful(body: str) -> str:
    return HEAD + body + "}\n"


def stateless(body: str) -> str:
    return STATELESS_HEAD + body + "}\n"


# --- REJECT: arity ---------------------------------------------------------

ARITY_TOO_FEW = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count);
  }
""")

ARITY_TOO_MANY = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner, 5n);
  }
""")

RAW_ARITY_ONE = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n);
  }
""")

RAW_ARITY_THREE = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n, this.blob, 7n);
  }
""")

DATA_ARITY_THREE = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addDataOutput(500n, this.blob, 7n);
  }
""")

# --- REJECT: state-value types ---------------------------------------------

STATE_VALUE_WRONG_TYPE = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.blob, this.owner);
  }
""")

# --- REJECT: the StatefulSmartContract gate --------------------------------

STATELESS_ADD_OUTPUT = stateless("""  public m(n: bigint) {
    this.addOutput(1000n, n);
    assert(n > 0n);
  }
""")

STATELESS_ADD_RAW_OUTPUT = stateless("""  public m(n: bigint) {
    this.addRawOutput(1000n, this.blob);
    assert(n > 0n);
  }
""")

STATELESS_ADD_DATA_OUTPUT = stateless("""  public m(n: bigint) {
    this.addDataOutput(1000n, this.blob);
    assert(n > 0n);
  }
""")

# --- ACCEPT (over-rejection guards) ----------------------------------------

SHAPE_EXACT = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
  }
""")

# A ByteString value in a PubKey state slot. TS's isSubtype treats the ByteString
# family as bidirectionally compatible, so TS ACCEPTS this and every tier must
# keep accepting it -- measured before this change, all seven tiers compiled it
# to the same script.
SHAPE_FAMILY_WIDENING = stateful("""  public m(n: bigint, b: ByteString) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count, b);
  }
""")

# A private helper's declared return type is discarded at parse time in every
# tier, so this infers as ``<unknown>``. TS escapes it; every port must too.
SHAPE_UNKNOWN_STATE_VALUE = stateful("""  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.anything(), this.owner);
  }
""")

# The one-mutable-property shape: the arity rule must be derived from the
# contract, not hardcoded.
ONE_PROP = """import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, blob: ByteString) {
    super(count, blob);
    this.count = count;
    this.blob = blob;
  }

  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob);
  }
}
"""


# A FixedArray state property. ``expand_fixed_arrays`` runs AFTER the
# typechecker in this tier and splits ``board`` into three scalar siblings, so
# the only call shape that lowers is the EXPANDED one below -- which the arity
# rule, counting the two DECLARED mutable properties, would reject. This is the
# contract from tests/test_r025_expand_fixed_arrays_field_preservation.py,
# checked into this repo and compiled by all six non-TS tiers; the TypeScript
# reference rejects it ("expects 3 argument(s) ... got 5"), which is a defect in
# the reference rule, not in this source.
FIXED_ARRAY_STATE = """import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n); }
}
"""


def errors_of(source: str) -> list[str]:
    result = compile_from_source_str_with_result(source, "C.runar.ts")
    return [d.message for d in result.diagnostics if d.severity == "error"]


def hex_of(source: str) -> str:
    result = compile_from_source_str_with_result(source, "C.runar.ts")
    if not result.success:
        pytest.fail(
            "expected this contract to compile; diagnostics: "
            + "; ".join(errors_of(source))
        )
    return result.script_hex


def assert_diagnostic(source: str, want: str) -> None:
    errs = errors_of(source)
    assert any(want in e for e in errs), f"expected {want!r}; got {errs}"


@pytest.mark.parametrize(
    "source,want",
    [
        (
            ARITY_TOO_FEW,
            "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 2",
        ),
        (
            ARITY_TOO_MANY,
            "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 4",
        ),
        (
            RAW_ARITY_ONE,
            "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 1",
        ),
        (
            RAW_ARITY_THREE,
            "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 3",
        ),
        (
            DATA_ARITY_THREE,
            "addDataOutput() expects 2 arguments (satoshis, scriptBytes), got 3",
        ),
    ],
    ids=[
        "addOutput-too-few",
        "addOutput-too-many",
        "addRawOutput-one",
        "addRawOutput-three",
        "addDataOutput-three",
    ],
)
def test_output_intrinsic_arity(source: str, want: str) -> None:
    assert_diagnostic(source, want)


def test_add_output_state_value_types() -> None:
    assert_diagnostic(
        STATE_VALUE_WRONG_TYPE,
        "addOutput() argument 2 (count) must be 'bigint', got 'ByteString'",
    )


@pytest.mark.parametrize(
    "source,want",
    [
        (STATELESS_ADD_OUTPUT, "addOutput() is only available in StatefulSmartContract"),
        (
            STATELESS_ADD_RAW_OUTPUT,
            "addRawOutput() is only available in StatefulSmartContract",
        ),
        (
            STATELESS_ADD_DATA_OUTPUT,
            "addDataOutput() is only available in StatefulSmartContract",
        ),
    ],
    ids=["addOutput", "addRawOutput", "addDataOutput"],
)
def test_output_intrinsics_are_stateful_only(source: str, want: str) -> None:
    assert_diagnostic(source, want)


@pytest.mark.parametrize(
    "source",
    [SHAPE_EXACT, SHAPE_FAMILY_WIDENING, SHAPE_UNKNOWN_STATE_VALUE],
    ids=[
        "exact-arity-and-types",
        "bytestring-value-in-pubkey-state-slot",
        "private-helper-call-is-unknown",
    ],
)
def test_accepted_output_shapes(source: str) -> None:
    assert hex_of(source)


def test_arity_is_derived_from_mutable_properties() -> None:
    """Non-vacuity: the arity rule must come from the contract's mutable
    properties, not a hardcoded number. A two-mutable-property contract wants
    three arguments; a one-mutable-property contract wants two.
    """
    assert hex_of(ONE_PROP)
    assert hex_of(SHAPE_EXACT)


def test_fixed_array_state_is_out_of_scope() -> None:
    """The carve-out above, pinned: a FixedArray-state contract stays
    compilable."""
    assert hex_of(FIXED_ARRAY_STATE)
