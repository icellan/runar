"""N-105 (1/2) -- a NUMBER in the scriptBytes position of addRawOutput /
addDataOutput.

Same shape as N-098, one argument slot over, and the slot is the created
output's LOCKING SCRIPT.

This tier ACCEPTED ``this.addRawOutput(1000n, n)`` with ``n: bigint``, and the
emitted script was byte-identical to the same contract written with
``n: ByteString`` -- measured, same digest. The operand is not converted:
whatever sits in that slot is spliced into the output serialization as the
output's script.

``_lower_add_raw_output`` takes OP_SIZE of the operand, varint-prefixes it and
concatenates it after the 8-byte amount. A script NUMBER on the stack is its
minimal little-endian encoding, so the covenant commits to an output whose
locking script IS those bytes. Executed on the real ``@bsv/sdk`` Spend engine
against the exact 55-opcode window all six tiers emit::

    n=0     -> scriptLen 0   locking script (empty)     -- anyone-can-spend
    n=81    -> scriptLen 1   0x51 = OP_1                -- anyone-can-spend
    n=118   -> scriptLen 1   0x76 = OP_DUP              -- anyone-can-spend
    n=1000  -> scriptLen 2   0xe8 0x03, 0xe8 invalid    -- unspendable

N-098's failure mode was a wrong amount or a frozen UTXO. This one can hand the
whole output to anybody who sees it, which is why it is a gate.

Ported from the TypeScript reference, wording included. ``<unknown>`` stays
ACCEPTED exactly as TS has it -- a private helper's declared return type is
discarded at parse time in every tier.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

HEAD = """import { StatefulSmartContract, ByteString, Ripemd160, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly flag: boolean;
  readonly blob: ByteString;
  readonly pkh: Ripemd160;

  constructor(count: bigint, base: bigint, flag: boolean, blob: ByteString, pkh: Ripemd160) {
    super(count, base, flag, blob, pkh);
    this.count = count;
    this.base = base;
    this.flag = flag;
    this.blob = blob;
    this.pkh = pkh;
  }

  private bytes(): ByteString { return this.blob; }

"""


def contract(body: str) -> str:
    return HEAD + body + "}\n"


# --- REJECT ----------------------------------------------------------------

RAW_BIGINT_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.base);
  }
""")

DATA_BIGINT_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.base);
  }
""")

RAW_BOOLEAN_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.flag);
  }
""")

# --- ACCEPT (over-rejection guards) ----------------------------------------

RAW_BYTESTRING_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob);
  }
""")

RAW_STATE_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.getStateScript());
  }
""")

# A ByteString SUBTYPE. TS's rule is ``is_subtype(script_type, "ByteString")``,
# not equality, so Ripemd160 must keep compiling.
RAW_SUBTYPE_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.pkh);
  }
""")

# A private helper's declared return type is discarded at parse time in every
# tier, so this infers as ``<unknown>``. TS escapes it; every port must too.
RAW_HELPER_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.bytes());
  }
""")

DATA_BYTESTRING_SCRIPT = contract("""  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.blob);
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
        (
            RAW_BIGINT_SCRIPT,
            "addRawOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
        ),
        (
            DATA_BIGINT_SCRIPT,
            "addDataOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
        ),
        (
            RAW_BOOLEAN_SCRIPT,
            "addRawOutput() second argument (scriptBytes) must be ByteString, got 'boolean'",
        ),
    ],
    ids=["addRawOutput-bigint", "addDataOutput-bigint", "addRawOutput-boolean"],
)
def test_rejects_non_bytestring_script_bytes(source: str, want: str) -> None:
    errs = errors_of(source)
    assert any(want in e for e in errs), f"expected {want!r}; got {errs}"


@pytest.mark.parametrize(
    "source",
    [
        RAW_BYTESTRING_SCRIPT,
        RAW_STATE_SCRIPT,
        RAW_SUBTYPE_SCRIPT,
        RAW_HELPER_SCRIPT,
        DATA_BYTESTRING_SCRIPT,
    ],
    ids=[
        "bytestring-property",
        "getStateScript",
        "bytestring-subtype-ripemd160",
        "private-helper-call-is-unknown",
        "addDataOutput-bytestring-property",
    ],
)
def test_accepted_script_bytes_positions(source: str) -> None:
    assert hex_of(source)


def test_script_bytes_operand_reaches_codegen() -> None:
    """Non-vacuity: "it compiled" would also hold for a tier that discarded the
    scriptBytes operand. Two DIFFERENT ByteString operands must lower to
    different scripts.
    """
    a = hex_of(RAW_BYTESTRING_SCRIPT)
    b = hex_of(RAW_STATE_SCRIPT)
    assert a != b, (
        "two different scriptBytes operands produced the same script -- "
        "the operand is being dropped"
    )


def test_bytestring_twin_still_compiles() -> None:
    """The reason this was invisible: the rejected source lowered EXACTLY like a
    correct one. The rule must remove the bad program and nothing else.
    """
    assert errors_of(RAW_BIGINT_SCRIPT), "the bigint-scriptBytes source was not rejected"
    assert errors_of(RAW_BYTESTRING_SCRIPT) == [], "the ByteString twin must still compile"
