"""F-192 (CX-BUG-074): ``is_stateful`` (and therefore ``is_terminal`` /
``artifact.anf``) was derived from ``len(state_fields) > 0`` instead of the
documented-authoritative ``program.parent_class``.

``ir/types.py`` says in ``ANFProgram.parent_class``'s own docstring that
``parent_class`` is authoritative "even though state_fields is empty" for a
StatefulSmartContract with zero mutable fields -- but
``_assemble_artifact`` gated both ``abi.methods[].is_terminal`` and the
top-level ``artifact.anf`` ANF snapshot on ``len(state_fields) > 0``. A
StatefulSmartContract with only readonly properties therefore kept its
correct ``parentClass`` (fixed separately for the SDK's terminal
sighash-trim gate, commit 304bfd31) but silently lost its terminal ABI flag
and its ANF state-tracking snapshot -- exactly the shape of
``examples/python/all-readonly-cleanstack/AllReadonlyCleanstack.runar.py``,
itself the regression fixture for issue #44 (a StatefulSmartContract with
ZERO mutable fields, only a readonly ``owner``) and a live, allowlist-free
conformance golden (``conformance/tests/all-readonly-cleanstack``).

What this proves: compiling that exact fixture produces an artifact whose
``parentClass`` is ``StatefulSmartContract``, whose ``state_fields`` is
empty (so the old ``len(state_fields) > 0`` heuristic is provably False
here), and whose ``abi.methods[0].is_terminal`` is ``True`` and whose
``artifact.anf`` is populated -- matching what the IR comment says must
hold regardless of state_fields' length.

What this does NOT prove: anything about the fallback path for IR loaded
without a ``parentClass`` (pre-F-038 ``--ir`` input) -- that path keeps the
old ``len(state_fields) > 0`` heuristic deliberately, since N-087's
fail-closed inference in ``ir/loader.py`` already requires
``parent_class == "StatefulSmartContract"`` (declared or inferred) before
any mutable property is accepted, so the fallback cannot disagree with
that inference. It also says nothing about the other six tiers, which
carry the same ``len(state_fields) > 0`` pattern in their own artifact
assemblers and were probed but intentionally not fixed here (see the F-192
remediation log).
"""

from __future__ import annotations

from pathlib import Path

from runar_compiler.compiler import compile_from_source_str_with_result

_FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "examples" / "python" / "all-readonly-cleanstack"
    / "AllReadonlyCleanstack.runar.py"
)


def test_zero_mutable_field_stateful_contract_keeps_terminal_flag_and_anf() -> None:
    source = _FIXTURE.read_text(encoding="utf-8")
    result = compile_from_source_str_with_result(source, "AllReadonlyCleanstack.runar.py")

    assert result.success, result.diagnostics
    artifact = result.artifact
    assert artifact is not None

    # Precondition: this fixture really is the zero-mutable-field case --
    # StatefulSmartContract with an empty state_fields list, so the old
    # len(state_fields) > 0 heuristic is provably False here.
    assert artifact.parent_class == "StatefulSmartContract"
    assert artifact.state_fields == []

    # The bug: both of these were lost when is_stateful was derived from
    # len(state_fields) instead of parent_class.
    methods_by_name = {m.name: m for m in artifact.abi.methods}
    assert methods_by_name["claim"].is_terminal is True
    assert artifact.anf is not None
    assert artifact.anf.contract_name == "AllReadonlyCleanstack"
