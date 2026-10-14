//! N-093 (user decisions R37/R38) — `@embedAlways` and `@sighash` on the eight
//! non-TS surfaces, each spelled as a native modifier that mirrors the
//! surface's readonly idiom (Rust tier port of the TS reference test
//! packages/runar-compiler/src/__tests__/n093-native-directives.test.ts):
//!
//!   .runar.sol   `ByteString immutable embedAlways x;`   `function f(..) public sighash(SINGLE | FORKID)`
//!   .runar.move  `#[embed_always] x: T,`                  `#[sighash(SINGLE | FORKID)] public fun f`
//!   .runar.go    `runar:"readonly,embedAlways"`            `//runar:sighash SINGLE|FORKID` above the func
//!   .runar.rs    `#[embed_always]`                         `#[sighash(SINGLE | FORKID)] pub fn f`
//!   .runar.py    `x: EmbedAlways[T]`                       `@public(sighash="SINGLE|FORKID")`
//!   .runar.zig   `x: runar.EmbedAlways(T)`                 `pub fn f(..) runar.Sighash("SINGLE|FORKID")`
//!   .runar.rb    `prop :x, T, embed_always: true`          `runar_sighash 'SINGLE|FORKID'` before the def
//!   .runar.java  `@EmbedAlways`                            `@Sighash("SINGLE|FORKID")`
//!
//! What this proves (Rust compiler tier):
//!   - each surface's port of examples/ts/compiler-directives/Directives and
//!     EmbedTags compiles, fold OFF and fold ON, to the pinned TS-reference
//!     script hex, keeps deployTag in the constructor slots, carries
//!     sigHashType 0x43 on spendSingle only, and lowers to the same ANF
//!     (source locations stripped) as the Rust tier's own .runar.ts compile of
//!     the original;
//!   - every malformed native spelling is REFUSED with the shared diagnostics
//!     the .runar.ts comment directive uses (non-public method, two spellings,
//!     malformed argument, bad flag set, directive on the wrong member kind),
//!     never a silent fall-back to ALL|FORKID or to DCE;
//!   - a COMMENT directive on a non-TS surface is still refused (the surface
//!     parsers drop comments) and the message names the native spelling.
//!
//! What it does NOT prove:
//!   - anything about the other six compiler tiers (each has its own port;
//!     cross-tier byte parity is the conformance suite's job);
//!   - on-chain behaviour of the bytes (the real-crypto witnesses do that);
//!   - that the examples build natively in their host languages (the example
//!     suites do that).

use std::path::PathBuf;

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions, CompileResult};

const DIRECTIVES_HEX: &str = "76009c63750078a900887b7bac7767519d76a90088ac68";
const EMBED_TAGS_HEX: &str = "57595b537a59a2695379a90088547a547aac777777";
const SINGLE_FORKID: i64 = 0x43;

/// (extension, Directives path, EmbedTags path — "" for Java: FixedArray
/// cannot be spelled there).
const SURFACES: &[(&str, &str, &str)] = &[
    (".runar.sol", "sol/compiler-directives/Directives.runar.sol", "sol/compiler-directives/EmbedTags.runar.sol"),
    (".runar.move", "move/compiler-directives/Directives.runar.move", "move/compiler-directives/EmbedTags.runar.move"),
    (".runar.go", "go/compiler-directives/Directives.runar.go", "go/compiler-directives/EmbedTags.runar.go"),
    (".runar.rs", "rust/compiler-directives/Directives.runar.rs", "rust/compiler-directives/EmbedTags.runar.rs"),
    (".runar.py", "python/compiler-directives/Directives.runar.py", "python/compiler-directives/EmbedTags.runar.py"),
    (".runar.zig", "zig/compiler-directives/Directives.runar.zig", "zig/compiler-directives/EmbedTags.runar.zig"),
    (".runar.rb", "ruby/compiler-directives/Directives.runar.rb", "ruby/compiler-directives/EmbedTags.runar.rb"),
    (".runar.java", "java/src/main/java/runar/examples/compiler-directives/Directives.runar.java", ""),
];

fn read(rel: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples").join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e))
}

fn directives_of(ext: &str) -> String {
    read(SURFACES.iter().find(|s| s.0 == ext).expect("unknown surface").1)
}

fn error_messages(r: &CompileResult) -> Vec<String> {
    r.diagnostics.iter().filter(|d| d.severity == Severity::Error).map(|d| d.message.clone()).collect()
}

fn build(src: &str, file: &str, fold_on: bool) -> CompileResult {
    let opts = CompileOptions { disable_constant_folding: !fold_on, ..Default::default() };
    let r = compile_from_source_str_with_result(src, Some(file), &opts);
    assert!(
        r.success && r.artifact.is_some(),
        "{} (fold_on={}) did not compile: {:?}",
        file,
        fold_on,
        error_messages(&r)
    );
    r
}

fn slot_names(r: &CompileResult) -> Vec<String> {
    let a = r.artifact.as_ref().unwrap();
    a.constructor_slots.iter().map(|s| a.abi.constructor.params[s.param_index].name.clone()).collect()
}

fn sighash_of(r: &CompileResult, method: &str) -> Option<i64> {
    r.artifact.as_ref().unwrap().abi.methods.iter().find(|m| m.name == method).and_then(|m| m.sig_hash_type)
}

/// The ANF IR as JSON without source locations (which name the surface file).
fn canonical_anf(r: &CompileResult) -> String {
    fn strip(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(m) => {
                m.remove("sourceLoc");
                for c in m.values_mut() {
                    strip(c);
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut v = serde_json::to_value(r.anf.as_ref().expect("ANF")).unwrap();
    strip(&mut v);
    v.to_string()
}

fn parse_errors(src: &str, file: &str) -> Vec<String> {
    parse_source(src, Some(file))
        .errors
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.message)
        .collect()
}

/// Replace exactly one occurrence, so a stale needle fails loudly.
fn swap(src: &str, from: &str, to: &str) -> String {
    assert_eq!(src.matches(from).count(), 1, "needle not found exactly once: {:?}", from);
    src.replacen(from, to, 1)
}

#[test]
fn n093_native_directives_match_ts_reference() {
    for fold_on in [false, true] {
        let ts_dir = build(&read("ts/compiler-directives/Directives.runar.ts"), "Directives.runar.ts", fold_on);
        let ts_emb = build(&read("ts/compiler-directives/EmbedTags.runar.ts"), "EmbedTags.runar.ts", fold_on);
        assert_eq!(ts_dir.script_hex.as_deref(), Some(DIRECTIVES_HEX), "fold_on={fold_on}: .runar.ts Directives drifted");
        assert_eq!(ts_emb.script_hex.as_deref(), Some(EMBED_TAGS_HEX), "fold_on={fold_on}: .runar.ts EmbedTags drifted");
        let ts_anf = canonical_anf(&ts_dir);
        for (ext, dir, emb) in SURFACES {
            let r = build(&read(dir), &format!("Directives{ext}"), fold_on);
            assert_eq!(r.script_hex.as_deref(), Some(DIRECTIVES_HEX), "{ext} fold_on={fold_on}: Directives hex");
            assert!(slot_names(&r).contains(&"deployTag".to_string()), "{ext}: deployTag missing: {:?}", slot_names(&r));
            assert_eq!(sighash_of(&r, "spendSingle"), Some(SINGLE_FORKID), "{ext}: spendSingle sigHashType");
            assert_eq!(sighash_of(&r, "spendAll"), None, "{ext}: spendAll sigHashType");
            assert_eq!(canonical_anf(&r), ts_anf, "{ext} fold_on={fold_on}: ANF differs from the .runar.ts original");
            if !emb.is_empty() {
                let e = build(&read(emb), &format!("EmbedTags{ext}"), fold_on);
                assert_eq!(e.script_hex.as_deref(), Some(EMBED_TAGS_HEX), "{ext} fold_on={fold_on}: EmbedTags hex");
            }
        }
    }
}

const NON_PUBLIC: &str = "@sighash directive on non-public method";
const MULTIPLE: &str = "more than one @sighash directive on this method";
const MALFORMED: &str = "@sighash: malformed directive";
const NO_FORKID: &str = "FORKID is mandatory on BSV";
const LOST_SIGHASH: &str = "@sighash directive is not attached to any method";
const LOST_EMBED: &str = "@embedAlways directive is not attached to any property";

/// (extension, label, from, to, expected error substring)
const NEGATIVES: &[(&str, &str, &str, &str, &str)] = &[
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
    (".runar.py", "no FORKID", "@public(sighash=\"SINGLE|FORKID\")", "@public(sighash=\"SINGLE\")", NO_FORKID),
    (".runar.py", "non-string argument", "@public(sighash=\"SINGLE|FORKID\")", "@public(sighash=SINGLE)", MALFORMED),
    (".runar.py", "unknown keyword", "@public(sighash=\"SINGLE|FORKID\")", "@public(mode=\"SINGLE|FORKID\")", MALFORMED),
    (".runar.py", "two decorators", "@public(sighash=\"SINGLE|FORKID\")", "@public(sighash=\"SINGLE|FORKID\")\n    @public(sighash=\"ALL|FORKID\")", MULTIPLE),
    (".runar.zig", "no FORKID", "runar.Sighash(\"SINGLE|FORKID\")", "runar.Sighash(\"SINGLE\")", NO_FORKID),
    (".runar.zig", "non-string argument", "runar.Sighash(\"SINGLE|FORKID\")", "runar.Sighash(SINGLE)", MALFORMED),
    (".runar.zig", "private fn", "pub fn spendSingle", "fn spendSingle", NON_PUBLIC),
    (".runar.rb", "no FORKID", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE'", NO_FORKID),
    (".runar.rb", "symbol argument", "runar_sighash 'SINGLE|FORKID'", "runar_sighash :single", MALFORMED),
    (".runar.rb", "two macros", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE|FORKID'\n  runar_sighash 'ALL|FORKID'", MULTIPLE),
    (".runar.rb", "private method", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_sighash 'SINGLE|FORKID'\n", NON_PUBLIC),
    (".runar.rb", "no following def", "\nend\n", "\n\n  runar_sighash 'ALL|FORKID'\nend\n", LOST_SIGHASH),
    (".runar.java", "no FORKID", "@Sighash(\"SINGLE|FORKID\")", "@Sighash(\"SINGLE\")", NO_FORKID),
    (".runar.java", "non-string argument", "@Sighash(\"SINGLE|FORKID\")", "@Sighash(1)", MALFORMED),
    (".runar.java", "two annotations", "@Sighash(\"SINGLE|FORKID\")", "@Sighash(\"SINGLE|FORKID\")\n    @Sighash(\"ALL|FORKID\")", MULTIPLE),
    (".runar.java", "no @Public", "    @Public\n    @Sighash", "    @Sighash", NON_PUBLIC),
    (".runar.java", "@Sighash on a field", "@Readonly @EmbedAlways ByteString", "@Readonly @Sighash(\"ALL|FORKID\") ByteString", LOST_SIGHASH),
    (".runar.java", "@EmbedAlways on a method", "@Sighash(\"SINGLE|FORKID\")", "@EmbedAlways", LOST_EMBED),
];

#[test]
fn n093_malformed_native_spelling_refused() {
    let mut failures = Vec::new();
    for (ext, label, from, to, want) in NEGATIVES {
        let errs = parse_errors(&swap(&directives_of(ext), from, to), &format!("Directives{ext}"));
        if !errs.join("\n").contains(want) {
            failures.push(format!("{ext}: {label}: want an error containing {want:?}, got {errs:?}"));
        }
    }
    assert!(failures.is_empty(), "{} case(s) failed:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn n093_native_spellings_compose_with_readonly() {
    // (label, ext, from, to, check: "hex" | "sighash" | "noDeployTag")
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        ("rs: #[embed_always] before #[readonly]", ".runar.rs", "#[readonly]\n    #[embed_always]", "#[embed_always]\n    #[readonly]", "hex"),
        ("rs: #[runar::sighash(...)]", ".runar.rs", "#[sighash(", "#[runar::sighash(", "sighash"),
        ("py: Readonly[EmbedAlways[T]]", ".runar.py", "EmbedAlways[ByteString]", "Readonly[EmbedAlways[ByteString]]", "hex"),
        ("zig: runar.Readonly(runar.EmbedAlways(T))", ".runar.zig", "runar.EmbedAlways(runar.ByteString)", "runar.Readonly(runar.EmbedAlways(runar.ByteString))", "hex"),
        ("sol: embedAlways before immutable", ".runar.sol", "ByteString immutable embedAlways deployTag", "ByteString embedAlways immutable deployTag", "hex"),
        ("rb: runar_sighash after runar_public", ".runar.rb", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_public sig: Sig, pub_key: PubKey\n  runar_sighash 'SINGLE|FORKID'\n", "sighash"),
        ("go: doc comment between directive and func", ".runar.go", "//runar:sighash SINGLE|FORKID\n", "//runar:sighash SINGLE|FORKID\n// SpendSingle commits to one output.\n", "sighash"),
        ("go: tag without embedAlways is not embedded", ".runar.go", "`runar:\"readonly,embedAlways\"`", "`runar:\"readonly\"`", "noDeployTag"),
    ];
    for (label, ext, from, to, check) in cases {
        let src = swap(&directives_of(ext), from, to);
        let r = build(&src, &format!("Directives{ext}"), false);
        match *check {
            "hex" => assert_eq!(r.script_hex.as_deref(), Some(DIRECTIVES_HEX), "{label}"),
            "sighash" => assert_eq!(sighash_of(&r, "spendSingle"), Some(SINGLE_FORKID), "{label}"),
            "noDeployTag" => assert!(!slot_names(&r).contains(&"deployTag".to_string()), "{label}: {:?}", slot_names(&r)),
            _ => unreachable!(),
        }
    }
}

#[test]
fn n093_comment_directive_on_non_ts_surface_names_native_spelling() {
    let names: &[(&str, &str, &str, &str, &str)] = &[
        (".runar.sol", "Solidity", "solidity", "the function modifier sighash(<FLAGS>)", "the property modifier embedAlways"),
        (".runar.move", "Move", "move", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
        (".runar.go", "Go DSL", "go", "the directive //runar:sighash <FLAGS>", "the struct tag option runar:\"readonly,embedAlways\""),
        (".runar.rs", "Rust", "rust", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
        (".runar.py", "Python", "python", "@public(sighash=\"<FLAGS>\")", "the wrapper type EmbedAlways[T]"),
        (".runar.zig", "Zig", "zig", "the return type runar.Sighash(\"<FLAGS>\")", "the type function runar.EmbedAlways(T)"),
        (".runar.rb", "Ruby", "ruby", "runar_sighash '<FLAGS>'", "the prop option embed_always: true"),
        (".runar.java", "Java", "java", "the annotation @Sighash(\"<FLAGS>\")", "the annotation @EmbedAlways"),
    ];
    for (ext, surface, doc, sig, emb) in names {
        let src = directives_of(ext);
        let comment = if *ext == ".runar.py" || *ext == ".runar.rb" { "#" } else { "//" };
        let file = format!("Directives{ext}");
        assert_eq!(
            parse_errors(&format!("{comment} @sighash SINGLE|FORKID\n{src}"), &file),
            vec![format!("@sighash directive (issue #123) is not supported as a comment by the {surface} surface parser; write it as {sig} (see docs/formats/{doc}.md)")],
            "{ext}: @sighash comment"
        );
        assert_eq!(
            parse_errors(&format!("{comment} @embedAlways\n{src}"), &file),
            vec![format!("@embedAlways directive (issue #109) is not supported as a comment by the {surface} surface parser; write it as {emb} (see docs/formats/{doc}.md)")],
            "{ext}: @embedAlways comment"
        );
    }
}

/// The constructor / init cases the TS reference refuses with
/// lost_directive_message: a constructor is neither a spending entry point nor
/// a field, so a sighash (or Java @EmbedAlways) on it would be dropped silently.
#[test]
fn n093_directive_on_constructor_refused() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (".runar.rs", "    pub fn spend_all", "    #[sighash(ALL | FORKID)]\n    pub fn init(&mut self) {}\n\n    pub fn spend_all", LOST_SIGHASH),
        (".runar.zig", ", deployTag: runar.ByteString) Directives {", ", deployTag: runar.ByteString) runar.Sighash(\"ALL|FORKID\") {", LOST_SIGHASH),
        (".runar.py", "    def __init__", "    @public(sighash=\"ALL|FORKID\")\n    def __init__", LOST_SIGHASH),
        (".runar.rb", "  def initialize", "  runar_sighash 'ALL|FORKID'\n  def initialize", LOST_SIGHASH),
        (".runar.java", "    Directives(Addr", "    @Sighash(\"ALL|FORKID\")\n    Directives(Addr", LOST_SIGHASH),
        (".runar.java", "    Directives(Addr", "    @EmbedAlways\n    Directives(Addr", LOST_EMBED),
    ];
    let mut failures = Vec::new();
    for (ext, from, to, want) in cases {
        let errs = parse_errors(&swap(&directives_of(ext), from, to), &format!("Directives{ext}"));
        if !errs.join("\n").contains(want) {
            failures.push(format!("{ext}: want an error containing {want:?}, got {errs:?}"));
        }
    }
    assert!(failures.is_empty(), "{} case(s) failed:\n{}", failures.len(), failures.join("\n"));
}
