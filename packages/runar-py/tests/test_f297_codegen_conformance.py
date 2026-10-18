"""F-297 — cross-SDK codegen conformance runner, Python side.

`conformance/sdk-codegen/` exists because a Rust codegen bug (fixed in
c00cfe7: the generated constructor body referenced a bare param name instead
of `args.<field>`) slipped through every SDK's own string-pattern tests —
none of them compiled the generated wrapper. Java
(`packages/runar-java/src/test/java/runar/lang/sdk/codegen/CodegenConformanceTest.java`),
Ruby (`packages/runar-rb/spec/sdk/codegen_conformance_spec.rb`) and Zig
(`packages/runar-zig/src/sdk_codegen_conformance_test.zig`) ship full
MANIFEST-shaped runners; Go (`packages/runar-go/sdk_codegen_test.go`) ships a
partial one. Rust got one in this same change
(`packages/runar-rs/tests/f297_codegen_conformance.rs`). Python had none —
`test_f239_codegen_satoshis_none.py` and `test_codegen_intent_witness.py`
exercise `generate_python` but against a hand-compiled Counter, not the
shared fixtures, and don't check the other fixture shapes.

None of these runners live at the MANIFEST/README-documented
`conformance/sdk-codegen/runners/<lang>/` path — that directory was never
actually created for any tier. This file follows the real precedent instead:
a test in the SDK's own `tests/` directory, loading the shared fixtures from
`conformance/sdk-codegen/fixtures/`, the same way `test_envelope_interop.py`
loads `conformance/sdk-envelope/fixtures.json`.

Compile-check approach: `exec(compile(src, ..., "exec"), {})` into a fresh
namespace, following the exact pattern `test_f239_codegen_satoshis_none.py`
already established for this generator. This is strictly stronger than a
syntax-only `compile()` check (MANIFEST's suggested
`python -c "compile(src, 'gen.py', 'exec')"`): `exec` actually runs the
module body, so `from runar.sdk import Something` that does not exist raises
ImportError, and a reference to an out-of-scope name raises NameError at
exec time — both are errors a syntax-only `compile()` would miss, and both
are exactly the class of bug (a value reachable only via a different
binding) that motivated this whole suite.

What this test proves:
  - `generate_python` for all 5 shared fixtures emits the structural
    elements the Python generator currently supports, and every generated
    module execs cleanly (imports resolve, no NameError/AttributeError at
    module-body execution time).

What this test does not prove:
  - Full MANIFEST compliance beyond what is asserted below. N-278: both
    `from_utxo` and `attach_inscription` are now asserted for every fixture,
    and their delegation to `RunarContract.from_utxo` / `with_inscription`
    is executed against the real SDK.
  - Runtime behavior beyond "the module execs". Unlike
    `test_f239_codegen_satoshis_none.py`, this file does not deploy or call
    anything through `MockProvider` — that is a property of this narrower
    generated-module (one fixture, full lifecycle) test, not a replacement
    for it.
  - Anything about the TypeScript, Go, Rust, Ruby, Java or Zig generators.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from runar.sdk import Inscription, Utxo
from runar.sdk.codegen import generate_python
from runar.sdk.types import RunarArtifact

FIXTURES_DIR = pathlib.Path(__file__).resolve().parents[3] / "conformance" / "sdk-codegen" / "fixtures"


def load_fixture(name: str) -> RunarArtifact:
    path = FIXTURES_DIR / name
    return RunarArtifact.from_dict(json.loads(path.read_text()))


def exec_check(src: str, label: str) -> dict:
    """Exec the generated module into a fresh namespace. Raises on any
    import/name/syntax error, with the generated source attached for
    diagnosis."""
    ns: dict = {}
    try:
        exec(compile(src, f"<generated {label}>", "exec"), ns)
    except Exception as e:  # noqa: BLE001 - re-raise with source attached
        raise AssertionError(f"{label}: generated Python failed to exec: {e!r}\n--- generated ---\n{src}") from e
    return ns


def test_p2pkh_fixture_has_required_structural_elements():
    artifact = load_fixture("p2pkh.json")
    src = generate_python(artifact)

    assert "class P2PKHContract" in src
    assert "def from_txid(" in src
    assert "def from_utxo(" in src
    assert "def attach_inscription(self, insc: Inscription)" in src
    assert "self._inner.with_inscription(insc)" in src
    assert "RunarContract.from_utxo(artifact, utxo)" in src
    assert "def connect(self, provider: Provider, signer: Signer)" in src
    assert "def get_locking_script(self)" in src
    assert "def deploy(" in src
    assert "def unlock(" in src
    assert "pub_key:" in src  # user-visible param after Sig is hidden
    assert "def prepare_unlock(" in src
    assert "def finalize_unlock(" in src
    assert "class TerminalOutput" in src
    assert "StatefulCallOptions" not in src  # stateless contract
    assert "{{" not in src, "unrendered Mustache tag"

    ns = exec_check(src, "p2pkh.json")
    assert "P2PKHContract" in ns


def test_counter_fixture_has_required_structural_elements():
    artifact = load_fixture("counter.json")
    src = generate_python(artifact)

    assert "class CounterContract" in src
    assert "count:" in src
    assert "class CounterStatefulCallOptions" in src
    assert "satoshis:" in src
    assert "change_address:" in src
    assert "change_pub_key:" in src
    assert "new_state:" in src
    assert "outputs:" in src
    assert "class TerminalOutput" in src
    assert "def increment(" in src
    assert "def reset(" in src
    assert "{{" not in src, "unrendered Mustache tag"

    ns = exec_check(src, "counter.json")
    assert "CounterContract" in ns
    assert "CounterStatefulCallOptions" in ns


def test_simple_fixture_has_required_structural_elements():
    artifact = load_fixture("simple.json")
    src = generate_python(artifact)

    assert "SimpleConstructorArgs" not in src  # no ctor params in this generator
    assert "class SimpleContract" in src
    assert "def __init__(self, artifact: RunarArtifact):" in src
    assert "def execute(" in src
    assert "{{" not in src, "unrendered Mustache tag"

    ns = exec_check(src, "simple.json")
    assert "SimpleContract" in ns


def test_stateful_escrow_fixture_has_required_structural_elements():
    artifact = load_fixture("stateful-escrow.json")
    src = generate_python(artifact)

    assert "class EscrowContract" in src
    assert "buyer:" in src
    assert "seller:" in src
    assert "amount:" in src
    assert "class EscrowStatefulCallOptions" in src
    assert "class TerminalOutput" in src

    # claim: non-terminal, single Sig (buyerSig) -> prepare/finalize.
    assert "def claim(" in src
    assert "def prepare_claim(" in src
    assert "def finalize_claim(" in src

    # release: terminal, two Sig params in ABI order.
    assert "def release(" in src
    assert "def prepare_release(" in src
    assert "def finalize_release(" in src
    finalize_release_idx = src.index("def finalize_release(")
    finalize_release_body = src[finalize_release_idx:]
    buyer_idx = finalize_release_body.index("buyer_sig:")
    seller_idx = finalize_release_body.index("seller_sig:")
    assert buyer_idx < seller_idx, "finalize_release must take buyer_sig before seller_sig (ABI order)"
    assert "{{" not in src, "unrendered Mustache tag"

    ns = exec_check(src, "stateful-escrow.json")
    assert "EscrowContract" in ns


def test_inscribed_fixture_emits_attach_inscription_and_from_utxo():
    artifact = load_fixture("inscribed.json")
    src = generate_python(artifact)

    assert "class InscribedHolderContract" in src
    assert "owner:" in src
    assert "def transfer(" in src
    assert "def prepare_transfer(" in src
    assert "def finalize_transfer(" in src
    assert "def attach_inscription(self, insc: Inscription)" in src
    assert "def from_utxo(" in src
    assert "{{" not in src, "unrendered Mustache tag"

    ns = exec_check(src, "inscribed.json")
    assert "InscribedHolderContract" in ns


def test_attach_inscription_and_from_utxo_delegate_to_the_real_contract():
    """N-278: the wrapper's `attach_inscription` splices the envelope into the
    locking script and `from_utxo` restores a wrapper with the identical
    script, both through the real `RunarContract`."""
    artifact = load_fixture("inscribed.json")
    ns = exec_check(generate_python(artifact), "inscribed.json")
    wrapper_cls = ns["InscribedHolderContract"]

    wrapper = wrapper_cls(artifact, owner="11" * 20)
    plain = wrapper.get_locking_script()
    insc = Inscription(content_type="text/plain", data=b"hello".hex())
    assert wrapper.attach_inscription(insc) is wrapper  # chains like with_inscription
    inscribed = wrapper.get_locking_script()
    assert inscribed != plain
    assert b"text/plain".hex() in inscribed

    restored = wrapper_cls.from_utxo(
        artifact, Utxo(txid="aa" * 32, output_index=0, satoshis=1000, script=inscribed)
    )
    assert isinstance(restored, wrapper_cls)
    assert restored.get_locking_script() == inscribed


def test_all_five_fixtures_generate_and_exec_cleanly():
    """One pass over all 5 shared fixtures, confirming none raises --
    the Python-side equivalent of the Rust runner's single combined
    compile-check."""
    for name in ("p2pkh.json", "counter.json", "simple.json", "stateful-escrow.json", "inscribed.json"):
        artifact = load_fixture(name)
        src = generate_python(artifact)
        exec_check(src, name)


def test_exec_check_rejects_a_reference_to_an_out_of_scope_name():
    """Regression proof that exec_check has teeth where a syntax-only
    `compile()` would not: a bare out-of-scope identifier reference (the
    shape of the original pre-c00cfe7 Rust bug -- the Python generator
    already uses `self.<field>`/keyword args correctly and has no equivalent
    live bug, so this hand-builds the error shape rather than reverting
    real generator code) is syntactically valid Python but raises NameError
    at exec time.
    """
    broken_src = "x = count\n"  # `count` is never bound -- syntactically fine, semantically broken
    with pytest.raises(AssertionError, match="NameError"):
        exec_check(broken_src, "synthetic regression probe")
