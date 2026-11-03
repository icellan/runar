"""N-093 (user decisions R37/R38) -- ``@embedAlways`` and ``@sighash`` on the
eight non-TS surfaces, each spelled as a native modifier that mirrors the
surface's readonly idiom (Python tier port of the TS reference test
packages/runar-compiler/src/__tests__/n093-native-directives.test.ts):

  .runar.sol   ``ByteString immutable embedAlways x;``   ``function f(..) public sighash(SINGLE | FORKID)``
  .runar.move  ``#[embed_always] x: T,``                  ``#[sighash(SINGLE | FORKID)] public fun f``
  .runar.go    ``runar:"readonly,embedAlways"``            ``//runar:sighash SINGLE|FORKID`` above the func
  .runar.rs    ``#[embed_always]``                         ``#[sighash(SINGLE | FORKID)] pub fn f``
  .runar.py    ``x: EmbedAlways[T]``                       ``@public(sighash="SINGLE|FORKID")``
  .runar.zig   ``x: runar.EmbedAlways(T)``                 ``pub fn f(..) runar.Sighash("SINGLE|FORKID")``
  .runar.rb    ``prop :x, T, embed_always: true``          ``runar_sighash 'SINGLE|FORKID'`` before the def
  .runar.java  ``@EmbedAlways``                            ``@Sighash("SINGLE|FORKID")``

What this proves (Python compiler tier):
  - each surface's port of examples/ts/compiler-directives/Directives and
    EmbedTags compiles, fold OFF and fold ON, to the pinned TS-reference
    script hex, keeps deployTag in the constructor slots, carries
    sigHashType 0x43 on spendSingle only, and lowers to the same ANF (source
    locations stripped) as this tier's own .runar.ts compile of the original;
  - every malformed native spelling is REFUSED with the shared diagnostics
    the .runar.ts comment directive uses (non-public method, two spellings,
    malformed argument, bad flag set, directive on the wrong member kind),
    never a silent fall-back to ALL|FORKID or to DCE;
  - a sighash (or Java @EmbedAlways) on a constructor / init is refused;
  - a COMMENT directive on a non-TS surface is still refused (the surface
    parsers drop comments) and the message names the native spelling.

What it does NOT prove:
  - anything about the other six compiler tiers (each has its own port;
    cross-tier byte parity is the conformance suite's job);
  - on-chain behaviour of the bytes (the real-crypto witnesses do that);
  - that the examples run natively in their host languages (the example
    suites do that).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from runar_compiler.compiler import _serialize_anf_program, compile_from_source_str_with_result
from runar_compiler.frontend.diagnostic import Severity
from runar_compiler.frontend.parser_dispatch import parse_source

EXAMPLES = Path(__file__).resolve().parent.parent.parent.parent / "examples"

DIRECTIVES_HEX = "76009c63750078a900887b7bac7767519d76a90088ac68"
EMBED_TAGS_HEX = "57595b537a59a2695379a90088547a547aac777777"
SINGLE_FORKID = 0x43

# (extension, Directives path, EmbedTags path -- None for Java: FixedArray
# cannot be spelled there).
SURFACES = [
    (".runar.sol", "sol/compiler-directives/Directives.runar.sol", "sol/compiler-directives/EmbedTags.runar.sol"),
    (".runar.move", "move/compiler-directives/Directives.runar.move", "move/compiler-directives/EmbedTags.runar.move"),
    (".runar.go", "go/compiler-directives/Directives.runar.go", "go/compiler-directives/EmbedTags.runar.go"),
    (".runar.rs", "rust/compiler-directives/Directives.runar.rs", "rust/compiler-directives/EmbedTags.runar.rs"),
    (".runar.py", "python/compiler-directives/Directives.runar.py", "python/compiler-directives/EmbedTags.runar.py"),
    (".runar.zig", "zig/compiler-directives/Directives.runar.zig", "zig/compiler-directives/EmbedTags.runar.zig"),
    (".runar.rb", "ruby/compiler-directives/Directives.runar.rb", "ruby/compiler-directives/EmbedTags.runar.rb"),
    (".runar.java", "java/src/main/java/runar/examples/compiler-directives/Directives.runar.java", None),
]


def _read(rel: str) -> str:
    return (EXAMPLES / rel).read_text(encoding="utf-8")


def _directives_of(ext: str) -> str:
    return _read(next(s[1] for s in SURFACES if s[0] == ext))


def _error_messages(r) -> list[str]:
    return [d.message for d in r.diagnostics if d.severity == Severity.ERROR]


def _build(src: str, file_name: str, fold_on: bool):
    r = compile_from_source_str_with_result(src, file_name, disable_constant_folding=not fold_on)
    assert r.success and r.artifact is not None, (
        f"{file_name} (fold_on={fold_on}) did not compile: {_error_messages(r)}"
    )
    return r


def _slot_names(r) -> list[str]:
    a = r.artifact
    return [a.abi.constructor.params[s.param_index].name for s in a.constructor_slots]


def _sighash_of(r, method: str):
    return next(m.sig_hash_type for m in r.artifact.abi.methods if m.name == method)


def _canonical_anf(r) -> str:
    """The ANF IR as JSON without source locations (which name the surface file)."""
    def strip(v):
        if isinstance(v, dict):
            return {k: strip(x) for k, x in v.items() if k != "sourceLoc"}
        if isinstance(v, list):
            return [strip(x) for x in v]
        return v
    return json.dumps(strip(_serialize_anf_program(r.anf)), sort_keys=True)


def _parse_errors(src: str, file_name: str) -> list[str]:
    return [d.message for d in parse_source(src, file_name).errors if d.severity == Severity.ERROR]


def _swap(src: str, frm: str, to: str) -> str:
    """Replace exactly one occurrence, so a stale needle fails loudly."""
    assert src.count(frm) == 1, f"needle not found exactly once: {frm!r}"
    return src.replace(frm, to, 1)


@pytest.mark.parametrize("fold_on", [False, True])
@pytest.mark.parametrize("ext,directives,embed_tags", SURFACES, ids=[s[0] for s in SURFACES])
def test_native_directives_match_ts_reference(ext, directives, embed_tags, fold_on):
    ts_dir = _build(_read("ts/compiler-directives/Directives.runar.ts"), "Directives.runar.ts", fold_on)
    ts_emb = _build(_read("ts/compiler-directives/EmbedTags.runar.ts"), "EmbedTags.runar.ts", fold_on)
    assert ts_dir.script_hex == DIRECTIVES_HEX, ".runar.ts Directives drifted"
    assert ts_emb.script_hex == EMBED_TAGS_HEX, ".runar.ts EmbedTags drifted"

    r = _build(_read(directives), f"Directives{ext}", fold_on)
    assert r.script_hex == DIRECTIVES_HEX
    assert "deployTag" in _slot_names(r), _slot_names(r)
    assert _sighash_of(r, "spendSingle") == SINGLE_FORKID
    assert _sighash_of(r, "spendAll") is None
    assert _canonical_anf(r) == _canonical_anf(ts_dir), "ANF differs from the .runar.ts original"
    if embed_tags is not None:
        e = _build(_read(embed_tags), f"EmbedTags{ext}", fold_on)
        assert e.script_hex == EMBED_TAGS_HEX


NON_PUBLIC = "@sighash directive on non-public method"
MULTIPLE = "more than one @sighash directive on this method"
MALFORMED = "@sighash: malformed directive"
NO_FORKID = "FORKID is mandatory on BSV"
LOST_SIGHASH = "@sighash directive is not attached to any method"
LOST_EMBED = "@embedAlways directive is not attached to any property"

# (extension, label, from, to, expected error substring)
NEGATIVES = [
    (".runar.sol", "no FORKID", "sighash(SINGLE | FORKID)", "sighash(SINGLE)", NO_FORKID),
    (".runar.sol", "comma-separated", "sighash(SINGLE | FORKID)", "sighash(SINGLE, FORKID)", MALFORMED),
    (".runar.sol", "two modifiers", "sighash(SINGLE | FORKID)", "sighash(SINGLE | FORKID) sighash(ALL | FORKID)", MULTIPLE),
    (".runar.sol", "private method", "public sighash(SINGLE | FORKID)", "private sighash(SINGLE | FORKID)", NON_PUBLIC),
    (".runar.move", "no FORKID", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE)]", NO_FORKID),
    (".runar.move", "comma-separated", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE, FORKID)]", MALFORMED),
    (".runar.move", "two attributes", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", MULTIPLE),
    (".runar.move", "private fun", "public fun spend_single", "fun spend_single", NON_PUBLIC),
    (".runar.move", "sighash on a field", "#[embed_always]", "#[sighash(SINGLE | FORKID)]", LOST_SIGHASH),
    (".runar.move", "embed_always on a fun", "#[sighash(SINGLE | FORKID)]", "#[embed_always]", LOST_EMBED),
    (".runar.move", "unknown attribute", "#[sighash(SINGLE | FORKID)]", "#[test]", "unsupported Move attribute #[test]"),
    (".runar.go", "no FORKID", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE", NO_FORKID),
    (".runar.go", "comma-separated", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE,FORKID", MALFORMED),
    (".runar.go", "glued", "//runar:sighash SINGLE|FORKID", "//runar:sighashSINGLE|FORKID", "unknown Go DSL directive '//runar:sighashSINGLE|FORKID'"),
    (".runar.go", "two directives", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE|FORKID\n//runar:sighash ALL|FORKID", MULTIPLE),
    (".runar.go", "unexported method", "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) SpendSingle", "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) spendSingleHelper() {}\n\nfunc (c *Directives) SpendSingle", NON_PUBLIC),
    (".runar.go", "not above a func", "type Directives struct", "//runar:sighash SINGLE|FORKID\ntype Directives struct", LOST_SIGHASH),
    (".runar.go", "unknown directive", "//runar:sighash SINGLE|FORKID", "//runar:inline", "unknown Go DSL directive '//runar:inline'"),
    (".runar.rs", "no FORKID", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE)]", NO_FORKID),
    (".runar.rs", "comma-separated", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE, FORKID)]", MALFORMED),
    (".runar.rs", "two attributes", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", MULTIPLE),
    (".runar.rs", "private fn", "pub fn spend_single", "fn spend_single", NON_PUBLIC),
    (".runar.rs", "sighash on a field", "#[embed_always]", "#[sighash(SINGLE | FORKID)]", LOST_SIGHASH),
    (".runar.rs", "embed_always on a fn", "#[sighash(SINGLE | FORKID)]", "#[embed_always]", LOST_EMBED),
    (".runar.py", "no FORKID", '@public(sighash="SINGLE|FORKID")', '@public(sighash="SINGLE")', NO_FORKID),
    (".runar.py", "non-string argument", '@public(sighash="SINGLE|FORKID")', "@public(sighash=SINGLE)", MALFORMED),
    (".runar.py", "unknown keyword", '@public(sighash="SINGLE|FORKID")', '@public(mode="SINGLE|FORKID")', MALFORMED),
    (".runar.py", "two decorators", '@public(sighash="SINGLE|FORKID")', '@public(sighash="SINGLE|FORKID")\n    @public(sighash="ALL|FORKID")', MULTIPLE),
    (".runar.zig", "no FORKID", 'runar.Sighash("SINGLE|FORKID")', 'runar.Sighash("SINGLE")', NO_FORKID),
    (".runar.zig", "non-string argument", 'runar.Sighash("SINGLE|FORKID")', "runar.Sighash(SINGLE)", MALFORMED),
    (".runar.zig", "private fn", "pub fn spendSingle", "fn spendSingle", NON_PUBLIC),
    (".runar.rb", "no FORKID", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE'", NO_FORKID),
    (".runar.rb", "symbol argument", "runar_sighash 'SINGLE|FORKID'", "runar_sighash :single", MALFORMED),
    (".runar.rb", "two macros", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE|FORKID'\n  runar_sighash 'ALL|FORKID'", MULTIPLE),
    (".runar.rb", "private method", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_sighash 'SINGLE|FORKID'\n", NON_PUBLIC),
    (".runar.rb", "no following def", "\nend\n", "\n\n  runar_sighash 'ALL|FORKID'\nend\n", LOST_SIGHASH),
    (".runar.java", "no FORKID", '@Sighash("SINGLE|FORKID")', '@Sighash("SINGLE")', NO_FORKID),
    (".runar.java", "non-string argument", '@Sighash("SINGLE|FORKID")', "@Sighash(1)", MALFORMED),
    (".runar.java", "two annotations", '@Sighash("SINGLE|FORKID")', '@Sighash("SINGLE|FORKID")\n    @Sighash("ALL|FORKID")', MULTIPLE),
    (".runar.java", "no @Public", "    @Public\n    @Sighash", "    @Sighash", NON_PUBLIC),
    (".runar.java", "@Sighash on a field", "@Readonly @EmbedAlways ByteString", '@Readonly @Sighash("ALL|FORKID") ByteString', LOST_SIGHASH),
    (".runar.java", "@EmbedAlways on a method", '@Sighash("SINGLE|FORKID")', "@EmbedAlways", LOST_EMBED),
]


@pytest.mark.parametrize("ext,label,frm,to,want", NEGATIVES, ids=[f"{n[0]}:{n[1]}" for n in NEGATIVES])
def test_malformed_native_spelling_refused(ext, label, frm, to, want):
    errs = _parse_errors(_swap(_directives_of(ext), frm, to), f"Directives{ext}")
    assert want in "\n".join(errs), f"{ext}: {label}: want an error containing {want!r}, got {errs!r}"


# (label, ext, from, to, check: "hex" | "sighash" | "noDeployTag")
COMPOSITIONS = [
    ("rs: #[embed_always] before #[readonly]", ".runar.rs", "#[readonly]\n    #[embed_always]", "#[embed_always]\n    #[readonly]", "hex"),
    ("rs: #[runar::sighash(...)]", ".runar.rs", "#[sighash(", "#[runar::sighash(", "sighash"),
    ("py: Readonly[EmbedAlways[T]]", ".runar.py", "EmbedAlways[ByteString]", "Readonly[EmbedAlways[ByteString]]", "hex"),
    ("zig: runar.Readonly(runar.EmbedAlways(T))", ".runar.zig", "runar.EmbedAlways(runar.ByteString)", "runar.Readonly(runar.EmbedAlways(runar.ByteString))", "hex"),
    ("sol: embedAlways before immutable", ".runar.sol", "ByteString immutable embedAlways deployTag", "ByteString embedAlways immutable deployTag", "hex"),
    ("rb: runar_sighash after runar_public", ".runar.rb", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_public sig: Sig, pub_key: PubKey\n  runar_sighash 'SINGLE|FORKID'\n", "sighash"),
    ("go: doc comment between directive and func", ".runar.go", "//runar:sighash SINGLE|FORKID\n", "//runar:sighash SINGLE|FORKID\n// SpendSingle commits to one output.\n", "sighash"),
    ("go: tag without embedAlways is not embedded", ".runar.go", '`runar:"readonly,embedAlways"`', '`runar:"readonly"`', "noDeployTag"),
]


@pytest.mark.parametrize("label,ext,frm,to,check", COMPOSITIONS, ids=[c[0] for c in COMPOSITIONS])
def test_native_spellings_compose_with_readonly(label, ext, frm, to, check):
    r = _build(_swap(_directives_of(ext), frm, to), f"Directives{ext}", False)
    if check == "hex":
        assert r.script_hex == DIRECTIVES_HEX, label
    elif check == "sighash":
        assert _sighash_of(r, "spendSingle") == SINGLE_FORKID, label
    else:
        assert "deployTag" not in _slot_names(r), f"{label}: {_slot_names(r)}"


COMMENT_NAMES = [
    (".runar.sol", "Solidity", "solidity", "the function modifier sighash(<FLAGS>)", "the property modifier embedAlways"),
    (".runar.move", "Move", "move", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
    (".runar.go", "Go DSL", "go", "the directive //runar:sighash <FLAGS>", 'the struct tag option runar:"readonly,embedAlways"'),
    (".runar.rs", "Rust", "rust", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
    (".runar.py", "Python", "python", '@public(sighash="<FLAGS>")', "the wrapper type EmbedAlways[T]"),
    (".runar.zig", "Zig", "zig", 'the return type runar.Sighash("<FLAGS>")', "the type function runar.EmbedAlways(T)"),
    (".runar.rb", "Ruby", "ruby", "runar_sighash '<FLAGS>'", "the prop option embed_always: true"),
    (".runar.java", "Java", "java", 'the annotation @Sighash("<FLAGS>")', "the annotation @EmbedAlways"),
]


@pytest.mark.parametrize("ext,surface,doc,sig,emb", COMMENT_NAMES, ids=[c[0] for c in COMMENT_NAMES])
def test_comment_directive_on_non_ts_surface_names_native_spelling(ext, surface, doc, sig, emb):
    src = _directives_of(ext)
    comment = "#" if ext in (".runar.py", ".runar.rb") else "//"
    file_name = f"Directives{ext}"
    assert _parse_errors(f"{comment} @sighash SINGLE|FORKID\n{src}", file_name) == [
        f"@sighash directive (issue #123) is not supported as a comment by the {surface} surface parser; "
        f"write it as {sig} (see docs/formats/{doc}.md)"
    ]
    assert _parse_errors(f"{comment} @embedAlways\n{src}", file_name) == [
        f"@embedAlways directive (issue #109) is not supported as a comment by the {surface} surface parser; "
        f"write it as {emb} (see docs/formats/{doc}.md)"
    ]


# The constructor / init cases the TS reference refuses with
# lost_directive_message: a constructor is neither a spending entry point nor
# a field, so a sighash (or Java @EmbedAlways) on it would be dropped silently.
CONSTRUCTOR_CASES = [
    (".runar.rs", "    pub fn spend_all", "    #[sighash(ALL | FORKID)]\n    pub fn init(&mut self) {}\n\n    pub fn spend_all", LOST_SIGHASH),
    (".runar.zig", ", deployTag: runar.ByteString) Directives {", ', deployTag: runar.ByteString) runar.Sighash("ALL|FORKID") {', LOST_SIGHASH),
    (".runar.py", "    def __init__", '    @public(sighash="ALL|FORKID")\n    def __init__', LOST_SIGHASH),
    (".runar.rb", "  def initialize", "  runar_sighash 'ALL|FORKID'\n  def initialize", LOST_SIGHASH),
    (".runar.java", "    Directives(Addr", '    @Sighash("ALL|FORKID")\n    Directives(Addr', LOST_SIGHASH),
    (".runar.java", "    Directives(Addr", "    @EmbedAlways\n    Directives(Addr", LOST_EMBED),
]


@pytest.mark.parametrize("ext,frm,to,want", CONSTRUCTOR_CASES, ids=[f"{c[0]}:{c[3][:9]}" for c in CONSTRUCTOR_CASES])
def test_directive_on_constructor_refused(ext, frm, to, want):
    errs = _parse_errors(_swap(_directives_of(ext), frm, to), f"Directives{ext}")
    assert want in "\n".join(errs), f"{ext}: want an error containing {want!r}, got {errs!r}"
