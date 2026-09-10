"""Issue #109 — ``/** @embedAlways */`` readonly-field DCE opt-out (Python port
of the TypeScript reference embed-always.test.ts).

The compiler eliminates a readonly property that no method references (an
emergent effect of ANF dead-binding DCE: the dead ``load_prop`` is dropped, so
no constructor slot is emitted). This silently removes deploy-time metadata
fields an author intends to recover from the on-chain script later.

Two surfaces:
  - Preservation: a ``/** @embedAlways */`` comment directive on a readonly
    field forces it into the locking script (a constructor slot).
  - Warning: an un-annotated, unreferenced readonly field emits a compile
    WARNING pointing at the directive.
"""

from __future__ import annotations

import re

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.diagnostic import Severity
from runar_compiler.frontend.parser_dispatch import parse_source


def _source(directive: str) -> str:
    """A stateless contract with a metadata field the body never reads.
    ``directive`` is spliced in immediately before the ``metadataId`` field.
    """
    return f"""
import {{ SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig }} from 'runar-lang';

class Meta extends SmartContract {{
  readonly pubKeyHash: Addr;
  {directive}
  readonly metadataId: ByteString;

  constructor(pubKeyHash: Addr, metadataId: ByteString) {{
    super(pubKeyHash, metadataId);
    this.pubKeyHash = pubKeyHash;
    this.metadataId = metadataId;
  }}

  public unlock(sig: Sig, pubKey: PubKey) {{
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }}
}}
"""


_WARN_RE = re.compile(
    r"readonly field 'metadataId' is not referenced .* eliminated by DCE.*@embedAlways",
    re.S,
)


def _errors(result):
    return [d for d in result.diagnostics if d.severity == Severity.ERROR]


def _warnings(result):
    return [d.message for d in result.diagnostics if d.severity == Severity.WARNING]


def _slot_param_names(result):
    ctor_params = result.artifact.abi.constructor.params
    return [ctor_params[s.param_index].name for s in result.artifact.constructor_slots]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TestEmbedAlwaysParser:
    def test_jsdoc_directive_sets_embed_always(self):
        r = parse_source(_source("/** @embedAlways */"), "Meta.runar.ts")
        assert not r.errors, r.error_strings()
        prop = next(p for p in r.contract.properties if p.name == "metadataId")
        assert prop.embed_always is True
        # Un-annotated sibling stays unset.
        other = next(p for p in r.contract.properties if p.name == "pubKeyHash")
        assert not other.embed_always

    def test_line_comment_directive(self):
        r = parse_source(_source("// @embedAlways"), "Meta.runar.ts")
        prop = next(p for p in r.contract.properties if p.name == "metadataId")
        assert prop.embed_always is True

    def test_no_directive_unset(self):
        r = parse_source(_source(""), "Meta.runar.ts")
        prop = next(p for p in r.contract.properties if p.name == "metadataId")
        assert not prop.embed_always

    def test_word_boundary_identifier_does_not_trip(self):
        # A comment mentioning `embedAlwaysMeta` must NOT set the flag.
        r = parse_source(_source("// see embedAlwaysMeta below"), "Meta.runar.ts")
        prop = next(p for p in r.contract.properties if p.name == "metadataId")
        assert not prop.embed_always


# ---------------------------------------------------------------------------
# Preservation
# ---------------------------------------------------------------------------

class TestEmbedAlwaysPreservation:
    def test_unannotated_field_eliminated(self):
        r = compile_from_source_str_with_result(_source(""), "Meta.runar.ts")
        assert r.success, [d.message for d in _errors(r)]
        names = _slot_param_names(r)
        assert "pubKeyHash" in names
        assert "metadataId" not in names

    def test_annotated_field_preserved(self):
        r = compile_from_source_str_with_result(
            _source("/** @embedAlways */"), "Meta.runar.ts"
        )
        assert r.success, [d.message for d in _errors(r)]
        names = _slot_param_names(r)
        assert "pubKeyHash" in names
        assert "metadataId" in names

    def test_annotated_hex_longer(self):
        off = compile_from_source_str_with_result(_source(""), "Meta.runar.ts")
        on = compile_from_source_str_with_result(
            _source("/** @embedAlways */"), "Meta.runar.ts"
        )
        assert on.script_hex != off.script_hex
        assert len(on.script_hex) > len(off.script_hex)


# ---------------------------------------------------------------------------
# Warning
# ---------------------------------------------------------------------------

class TestEmbedAlwaysWarning:
    def test_warns_on_unannotated_unreferenced_readonly(self):
        r = compile_from_source_str_with_result(_source(""), "Meta.runar.ts")
        assert r.success  # warning is non-fatal
        msgs = "\n".join(_warnings(r))
        assert _WARN_RE.search(msgs), msgs

    def test_no_warn_when_annotated(self):
        r = compile_from_source_str_with_result(
            _source("/** @embedAlways */"), "Meta.runar.ts"
        )
        msgs = "\n".join(_warnings(r))
        assert "metadataId" not in msgs, msgs

    def test_no_warn_for_referenced_readonly(self):
        referenced = """
import { SmartContract, assert, Addr, PubKey, Sig, hash160, checkSig } from 'runar-lang';

class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;

  constructor(pubKeyHash: Addr) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"""
        r = compile_from_source_str_with_result(referenced, "P2PKH.runar.ts")
        assert r.success
        assert "pubKeyHash" not in "\n".join(_warnings(r))


# ---------------------------------------------------------------------------
# Regression: @embedAlways must survive a FIXED-POINT DCE.
#
# The preservation used to be an alias pair: the injected ``load_prop`` plus a
# ``load_const("@ref:<t>")`` binding whose only job was to make the ``load_prop``
# look referenced. That survives ONE DCE sweep but not the fixed-point loop:
# sweep 1 drops the now-unreferenced alias, sweep 2 then drops the ``load_prop``
# it was protecting, and BOTH halves vanish.
#
# DCE only runs from inside the EC optimizer's changed-gate, so the probe has to
# arm it: ``ecMulGen(1n)`` folds to the generator constant, which flips
# ``changed`` and lets dead-binding elimination run.
#
# Zig marks the injected ``load_prop`` itself with ``preserve = True`` and reads
# that flag in ``has_side_effect``; this tier now does the same.
# ---------------------------------------------------------------------------

def _ec_source(directive: str) -> str:
    """EC-armed probe. ``metadataId`` carries DIRECTIVE; ``droppedField`` is an
    un-annotated, unreferenced control that MUST still be eliminated, so a
    passing test cannot be satisfied by "retain everything".
    """
    return f"""
import {{ SmartContract, assert, Addr, PubKey, Sig, ByteString, hash160, checkSig, ecMulGen, ecPointX }} from 'runar-lang';

class EcMeta extends SmartContract {{
  readonly pubKeyHash: Addr;
  {directive}
  readonly metadataId: ByteString;
  readonly droppedField: ByteString;

  constructor(pubKeyHash: Addr, metadataId: ByteString, droppedField: ByteString) {{
    super(pubKeyHash, metadataId, droppedField);
    this.pubKeyHash = pubKeyHash;
    this.metadataId = metadataId;
    this.droppedField = droppedField;
  }}

  public unlock(sig: Sig, pubKey: PubKey) {{
    const g = ecMulGen(1n);
    assert(ecPointX(g) > 0n);
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }}
}}
"""


class TestEmbedAlwaysSurvivesFixedPointDce:
    def test_annotated_field_survives_ec_armed_dce(self):
        r = compile_from_source_str_with_result(
            _ec_source("/** @embedAlways */"), "EcMeta.runar.ts"
        )
        assert r.success, [d.message for d in _errors(r)]
        names = _slot_param_names(r)
        assert "metadataId" in names, f"@embedAlways field dropped by fixed-point DCE: {names}"

    def test_unannotated_dead_field_still_eliminated(self):
        # Control: the fix must not degenerate into "keep every load_prop".
        for directive in ("", "/** @embedAlways */"):
            r = compile_from_source_str_with_result(_ec_source(directive), "EcMeta.runar.ts")
            assert r.success, [d.message for d in _errors(r)]
            names = _slot_param_names(r)
            assert "droppedField" not in names, f"directive={directive!r}: {names}"

    def test_ec_armed_annotated_hex_longer(self):
        off = compile_from_source_str_with_result(_ec_source(""), "EcMeta.runar.ts")
        on = compile_from_source_str_with_result(
            _ec_source("/** @embedAlways */"), "EcMeta.runar.ts"
        )
        assert on.script_hex != off.script_hex
        assert len(on.script_hex) > len(off.script_hex)
