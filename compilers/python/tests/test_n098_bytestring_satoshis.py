"""Port of the TypeScript reference test
``packages/runar-compiler/src/__tests__/n098-bytestring-satoshis.test.ts``.

N-098 — a ByteString in the SATOSHIS position of an output intrinsic.

This tier ACCEPTED all three shapes. It was not a missing diagnostic: the
ByteString was lowered into the satoshis slot with NO conversion, and the
emitted script was byte-identical to the same contract written with
``blob: bigint`` — 1358 hexchars, same digest, in all six accepting tiers.

``_lower_add_output`` prepends the satoshis operand as ``OP_8 OP_NUM2BIN``, so
the covenant commits to whatever those bytes decode to as a script number.
Executed on the real ``@bsv/sdk`` Spend engine with ``blob = 0x2a``, a
42-satoshi continuation VALIDATES and the 1000-satoshi one the author funded is
REJECTED. Bigger blobs fail shut rather than safe: ``0xcafebabefeed0001``
demands 7.2e16 satoshis and a 20-byte hash aborts the script at ``OP_NUM2BIN``,
leaving the UTXO permanently unspendable.

The rule ported here is the TypeScript reference's, wording included. Only the
FIRST argument is checked. TS additionally checks arity, the state-value types
and the ``scriptBytes`` argument; none of those are ported here and none of them
are this finding.

The ACCEPT block carries the real risk in a change like this. ``<unknown>`` must
stay accepted: a private helper's declared return type is discarded at parse
time in every tier, so ``this.sats()`` infers as ``<unknown>``, and TS has always
escaped it here.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

HEAD = """import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, base: bigint, blob: ByteString) {
    super(count, base, blob);
    this.count = count;
    this.base = base;
    this.blob = blob;
  }

  private sats(): bigint { return this.base; }

"""


def contract(body: str) -> str:
    return HEAD + body + "}\n"


# --- REJECT ----------------------------------------------------------------

ADD_OUTPUT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.blob, this.count);
  }
""")

ADD_RAW_OUTPUT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(this.blob, this.blob);
  }
""")

ADD_DATA_OUTPUT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(this.blob, this.blob);
  }
""")

# --- ACCEPT (over-rejection guards) ----------------------------------------

LITERAL_SATS = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
  }
""")

PARAM_SATS = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(n, this.count);
  }
""")

PROPERTY_SATS = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.base, this.count);
  }
""")

# A private helper's declared return type is discarded at parse time in EVERY
# tier, so this infers as ``<unknown>``. It must stay ACCEPTED.
HELPER_SATS = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.sats(), this.count);
  }
""")


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


@pytest.mark.parametrize(
    "source,want",
    [
        (ADD_OUTPUT, "addOutput() first argument (satoshis) must be bigint, got 'ByteString'"),
        (
            ADD_RAW_OUTPUT,
            "addRawOutput() first argument (satoshis) must be bigint, got 'ByteString'",
        ),
        (
            ADD_DATA_OUTPUT,
            "addDataOutput() first argument (satoshis) must be bigint, got 'ByteString'",
        ),
    ],
    ids=["addOutput", "addRawOutput", "addDataOutput"],
)
def test_rejects_bytestring_satoshis(source: str, want: str) -> None:
    errs = errors_of(source)
    assert any(want in e for e in errs), f"expected {want!r}; got {errs}"


@pytest.mark.parametrize(
    "source",
    [LITERAL_SATS, PARAM_SATS, PROPERTY_SATS, HELPER_SATS],
    ids=["literal", "parameter", "property", "private-helper-call-is-unknown"],
)
def test_accepted_satoshis_positions(source: str) -> None:
    assert hex_of(source)


def test_satoshis_operand_reaches_codegen() -> None:
    """Non-vacuity: "it compiled" would also hold for a tier that discarded the
    satoshis operand entirely. A literal and a runtime parameter must lower to
    DIFFERENT scripts. Every tier's own N-098 test makes this same assertion.
    """
    lit = hex_of(LITERAL_SATS)
    param = hex_of(PARAM_SATS)
    assert lit != param, (
        "literal and parameter satoshis produced the same script — "
        "the operand is being dropped"
    )
    assert "02e803" in lit  # PUSH(2) 0xe8 0x03 == 1000
