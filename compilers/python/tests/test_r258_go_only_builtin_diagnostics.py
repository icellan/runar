"""R-258 / R-259 (CL-GAP-001, CL-GAP-002): the Python tier reports a real Runar
builtin it does not implement as an unknown function.

Eight builtins are in the Go tier's table and not in Python's:

    assertGroth16WitnessAssisted        bn254Pairing
    assertGroth16WitnessAssistedWithMSM bn254MultiPairing3
    groth16PublicInput                  bn254MultiPairing4
    merkleRootPoseidon2KB               verifySP1FRI

All eight belong to families CLAUDE.md scopes to the Go tier, so their ABSENCE
here is policy, not a gap — that part of both findings is correct and nothing
needs porting. What is wrong is the diagnostic:

    unknown function 'bn254Pairing' -- only Runar built-in functions
    and contract methods are allowed

`bn254Pairing` IS a Runar built-in function. An author who reads that goes
looking for a typo or a missing import, which is the one thing that is not
wrong; what they need to be told is that this family compiles in the Go tier.
The Java tier already says exactly that for the families it skips.

CL-GAP-001 asks for "a test asserting the Python tier rejects a contract calling
any bn254 pairing builtin with a clear 'Go tier only' diagnostic". This is that
test, widened to all eight — the same sentence is owed for each.
"""

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

GO_ONLY_BUILTINS = [
    "assertGroth16WitnessAssisted",
    "assertGroth16WitnessAssistedWithMSM",
    "groth16PublicInput",
    "bn254Pairing",
    "bn254MultiPairing3",
    "bn254MultiPairing4",
    "merkleRootPoseidon2KB",
    "verifySP1FRI",
]


def source_calling(fn: str) -> str:
    return f"""
import {{ SmartContract, assert, {fn} }} from 'runar-lang';

class Probe extends SmartContract {{
  readonly limit: bigint;

  constructor(limit: bigint) {{
    super(limit);
    this.limit = limit;
  }}

  public unlock(a: bigint, b: bigint) {{
    assert({fn}(a, b) === this.limit);
  }}
}}
"""


def diagnostics(fn: str) -> str:
    res = compile_from_source_str_with_result(source_calling(fn), "Probe.runar.ts")
    assert not res.success, f"{fn} compiled in the Python tier"
    return "\n".join(d.message for d in res.diagnostics)


@pytest.mark.parametrize("fn", GO_ONLY_BUILTINS)
def test_a_go_only_builtin_is_not_called_unknown(fn):
    msg = diagnostics(fn)
    assert "unknown function" not in msg, (
        f"{fn} is a real Runar builtin, scoped to the Go tier by policy. Calling "
        f"it 'unknown' sends the author looking for a typo: {msg}"
    )


@pytest.mark.parametrize("fn", GO_ONLY_BUILTINS)
def test_a_go_only_builtin_names_the_builtin_and_the_policy(fn):
    msg = diagnostics(fn)
    assert fn in msg, msg
    assert "Go" in msg, (
        "the diagnostic must say which tier does implement it: " + msg
    )


def test_a_genuinely_unknown_name_is_still_unknown():
    """The control. Without it, 'never say unknown' would pass every case above."""
    msg = diagnostics("definitelyNotARunarBuiltin")
    assert "unknown function" in msg, msg


def test_a_builtin_python_does_implement_still_compiles():
    """And the refusal table must not swallow a builtin this tier has."""
    src = """
import { SmartContract, assert, sha256 } from 'runar-lang';

class Ok extends SmartContract {
  readonly h: ByteString;

  constructor(h: ByteString) {
    super(h);
    this.h = h;
  }

  public unlock(x: ByteString) {
    assert(sha256(x) === this.h);
  }
}
"""
    res = compile_from_source_str_with_result(src, "Ok.runar.ts")
    assert res.success, "\n".join(d.message for d in res.diagnostics)
