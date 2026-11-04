"""N-257: a LEGITIMATE (no Rabin, no malicious intent) TS-surface tuple-form
``this.addOutput(satoshis, [v1, v2])`` crashed the Python compiler with
``RuntimeError: value 't13' not found on stack`` instead of compiling.

Root cause: ``this.addOutput(...)`` reaches ``anf_lower.py``'s call-lowering
dispatch through TWO different branches depending on the AST shape the parser
produced for the call:

- the ``PropertyAccessExpr`` branch, which calls
  ``_flatten_add_output_args`` to unwrap a trailing array-literal value list
  into individual state values, mirroring ``flattenAddOutputArgs`` in
  ``04-anf-lower.ts``. Only ``parser_zig.py`` normalises
  ``addOutput``/``addRawOutput``/``addDataOutput``/``getStateScript`` to a
  bare property access outright, and ``parser_ruby.py``'s
  ``_rewrite_bare_method_calls`` does the same for a BARE
  ``add_output(...)`` call with no explicit receiver;
- the ``MemberExpr`` branch, which did NOT call
  ``_flatten_add_output_args`` and instead lowered the array literal as a
  single ``array_literal``-kind ANF value. This is the branch every other
  explicit-receiver call hits: ``parser_ts.py``'s ``_parse_postfix`` and
  ``parser_ruby.py``'s ``_parse_postfix_from`` both build a ``MemberExpr``
  callee for every ``this.x(...)``/``self.x(...)`` call (verified directly;
  Solidity/Rust/Go/Java were not individually re-verified here but share the
  same generic postfix-parsing shape and no addOutput-specific
  normalisation).

``array_literal`` is a METADATA-only ANF binding (used by ``checkMultiSig``'s
sigs/pks lists) that never pushes anything onto the actual script stack. When
``_lower_add_output`` tried to bring that binding's name to the top of the
stack, nothing was there, so ``bring_to_top`` raised.

The TypeScript reference computes ``normalizedAddOutputArgs =
flattenAddOutputArgs(expr.args)`` ONCE per call and uses it in BOTH its
``property_access`` and ``member_expr`` addOutput branches (04-anf-lower.ts),
so TS compiles this source successfully. This test proves Python now matches.
"""

from __future__ import annotations

from runar_compiler.compiler import compile_from_source_str_with_result

SOURCE = """import { StatefulSmartContract } from 'runar-lang';

class TupleAddOutput extends StatefulSmartContract {
  count: bigint;
  flag: bigint;
  constructor(count: bigint, flag: bigint) {
    super(count, flag);
    this.count = count;
    this.flag = flag;
  }
  public bump(x: bigint): void {
    this.addOutput(1000n, [this.count, x]);
  }
}
"""

# Captured from the TypeScript reference compiler (`compile()` in
# packages/runar-compiler/src/index.ts) compiling the byte-identical source
# above. Go's compiler (which also unwraps the array literal before codegen)
# emits the SAME hex. Not a conformance golden -- a plain literal pinned in
# this test file to prove byte-for-byte parity with the reference tier.
EXPECTED_HEX = (
    "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f51"
    "7f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c"
    "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
    "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafe"
    "ffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f"
    "82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f8292"
    "7f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82"
    "927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c"
    "7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e"
    "23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e"
    "827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c"
    "1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c"
    "6375547f77677602ff009c6375587f776775527f7768686856798252947b7c7f8201119d517f"
    "75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f75825894"
    "7f758260947f77587f7c817c8102e8035279577a5879016a7e7b58807e7c58807e827602fd00"
    "9f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f"
    "7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e557a557a00787c9c9163041976"
    "a9147b7e0288ac7e7c58807c7e67007b7577687eaa537a820128947f7701207f7587777777"
)


def test_tuple_form_add_output_via_member_expr_compiles_like_ts():
    """PROVES: a legitimate (non-Rabin) TS-surface ``this.addOutput(sats,
    [v1, v2])`` -- reached only through the MemberExpr callee branch that the
    TS/Solidity/Rust/Go/Java surface parsers always produce for ``this.x()``
    calls -- now compiles successfully in Python, with hex byte-identical to
    the TypeScript reference compiler.

    DOES NOT PROVE: that every OTHER multi-value tuple shape (three or more
    elements, a tuple used with addRawOutput/addDataOutput, a tuple nested
    inside a branch arm) is unaffected; those are untouched by this fix's
    scope (only the ``addOutput`` MemberExpr branch was missing the
    unwrap) and are not separately exercised here. Also does not prove
    on-chain spendability -- that is the conformance/oracle suite's job.
    """
    result = compile_from_source_str_with_result(SOURCE, "TupleAddOutput.runar.ts")
    assert result.success, f"diagnostics: {result.diagnostics}"
    assert result.script_hex == EXPECTED_HEX
