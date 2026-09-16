//! The ratchet on `.runar.rs` contracts that call a byte builtin and are NOT
//! compiled as native Rust.
//!
//! # Why
//!
//! A `.runar.rs` contract is meant to be valid Rust as well as valid Rúnar:
//! `cargo test` checks its business logic against the mocks in
//! `packages/runar-rs` while `runar::compile_check` checks it as Rúnar. A
//! contract that is never `#[path]`-included in a registered test target gets
//! only the second half, silently.
//!
//! Eight builtins that `docs/formats/rust.md` documents as callable — `len`,
//! `split`, `left`, `right`, `int2str`, `int_2_str`, `reverse_bytes`,
//! `to_byte_string` — had NO mock in `packages/runar-rs`. Seven of the 84
//! `.runar.rs` example contracts call one, and every one of the seven was
//! therefore uncompilable as Rust. Six of them are wired up now. One is not,
//! and this file pins which one.
//!
//! # Why a set and not a count
//!
//! `excluded.len() <= 1` is a guard that stops being read: a bound that only
//! has to be "not worse" absorbs the next exclusion without argument. This
//! asserts the SET, so a second exclusion fails here and has to justify itself
//! in the same commit — and removing one fails here too, which is correct: it
//! should be deliberate and it should say so.
//!
//! # Non-vacuity
//!
//! The universe this scans is derived, not declared: it is every `.runar.rs`
//! under `examples/rust` that CALLS one of the eight. If that derivation broke
//! and returned nothing, the excluded set would be empty and would match an
//! empty expectation — so `the_universe_is_not_empty` pins its size, and
//! `the_scanner_answers_a_known_tree` runs both halves of the scan over a
//! synthetic tree whose answer is known. That synthetic tree includes the two
//! ways this scan has already produced a wrong count today: a builtin named in
//! PROSE in a doc comment is not a call, and a `#[path]` shown inside a comment
//! is not an include. It also covers a builtin name inside a STRING literal,
//! which the first draft of this scanner counted as a call.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// THE SET
// ---------------------------------------------------------------------------

/// The `.runar.rs` contracts that call one of the eight byte builtins and
/// still cannot be compiled as native Rust. Paths are relative to
/// `examples/rust`. Each is justified at the top of the named file; see
/// `every_exclusion_carries_a_written_reason`.
///
/// The one remaining blocker is NOT a missing mock and no longer a ByteString
/// literal either: `self.add_output(...)` is a method the `#[runar::contract]`
/// proc macro in `packages/runar-rs-macros` does not generate. The output
/// intrinsics (`add_output`, `add_data_output`, `add_raw_output`) need an
/// output-recording surface on the mock contract rather than a mock function;
/// that blocks nine `.runar.rs` contracts in total and is orthogonal to the
/// byte builtins.
///
/// The ByteString-literal blocker that used to hold `r1-k1-wallet` here is
/// gone. `spec/grammar.md` section 11 makes `toByteString '(' StringLiteral
/// ')'` the ByteStringLiteral production, and all seven tiers now fold it to a
/// literal in ANF lowering, so `to_byte_string("41000000")` — the only
/// spelling that is both valid Rust and valid Rúnar — reaches the IR
/// indistinguishable from the bare literal the other eight surfaces carry.
const EXCLUDED: &[&str] = &["branched-readonly-len/BranchedReadonlyLen.runar.rs"];

/// The header every excluded contract must carry. A fixed marker, rather than
/// "some comment", is what stops a future exclusion from being justified by
/// whatever prose already happened to be at the top of the file.
const REASON_MARKER: &str = "// EXCLUDED FROM NATIVE RUST COMPILATION";

/// The builtins this commit added to `packages/runar-rs`. A contract calling
/// any of them is in the universe this ratchet governs.
const BYTE_BUILTINS: &[&str] =
    &["len", "split", "left", "right", "int2str", "int_2_str", "reverse_bytes", "to_byte_string"];

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// `examples/rust`, one level up from this directory.
fn examples_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Rust source with `//` line comments and `/* */` block comments removed.
///
/// Comment text is prose, and prose naming a builtin is not a call to it — the
/// distinction that produced a wrong count when this gap was first measured
/// with a plain grep.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_string = false;
    let mut depth = 0usize;
    while i < b.len() {
        if depth > 0 {
            if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                depth -= 1;
                i += 2;
            } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                depth += 1;
                i += 2;
            } else {
                if b[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        if in_string {
            if b[i] == b'\\' && i + 1 < b.len() {
                out.push(b[i] as char);
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if b[i] == b'"' {
                in_string = false;
            }
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        if b[i] == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
            continue;
        }
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            depth = 1;
            i += 2;
            continue;
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// The bodies of string literals replaced by spaces.
///
/// A builtin name inside a string is text, not a call — the same mistake as
/// counting one inside a comment. `path_mod_includes` needs the string bodies,
/// so this is a second pass rather than part of `strip_comments`.
fn blank_string_literals(code: &str) -> String {
    let b = code.as_bytes();
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    while i < b.len() {
        // A char literal can hold a quote (`'"'`), which would otherwise open a
        // string that never closes. A lifetime (`&'static`) is not one, and is
        // left alone because the character after the tick is not a quote.
        if b[i] == b'\'' && i + 2 < b.len() && b[i + 1] == b'"' && b[i + 2] == b'\'' {
            out.push_str("' '");
            i += 3;
            continue;
        }
        if b[i] != b'"' {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        out.push('"');
        i += 1;
        while i < b.len() {
            if b[i] == b'\\' && i + 1 < b.len() {
                out.push_str("  ");
                i += 2;
                continue;
            }
            if b[i] == b'"' {
                out.push('"');
                i += 1;
                break;
            }
            out.push(if b[i] == b'\n' { '\n' } else { ' ' });
            i += 1;
        }
    }
    out
}

/// Does `code` contain a free-function call to `name`?
///
/// The character before the name must not be an identifier character or a `.`,
/// so `data.len()` — a Rust method on a slice, not the Rúnar builtin — does not
/// count, and neither does `some_len(`. Pass comment-stripped,
/// string-literal-blanked source.
fn calls_builtin(code: &str, name: &str) -> bool {
    let bytes = code.as_bytes();
    let mut from = 0;
    while let Some(rel) = code[from..].find(name) {
        let start = from + rel;
        let end = start + name.len();
        from = start + 1;
        if start > 0 {
            let p = bytes[start - 1];
            if p == b'.' || p == b'_' || p.is_ascii_alphanumeric() {
                continue;
            }
        }
        let mut j = end;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\n' || bytes[j] == b'\t') {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'(' {
            return true;
        }
    }
    false
}

/// Every `*.runar.rs` under `root`, relative to it, sorted.
fn all_contracts(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().and_then(|n| n.to_str()) != Some("target") {
                    stack.push(p);
                }
            } else if p.to_string_lossy().ends_with(".runar.rs") {
                out.push(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    out
}

/// The contracts that call at least one of the eight byte builtins.
fn universe(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for rel in all_contracts(root) {
        let src = fs::read_to_string(root.join(&rel)).expect("reading a contract");
        let code = blank_string_literals(&strip_comments(&src));
        if BYTE_BUILTINS.iter().any(|b| calls_builtin(&code, b)) {
            out.insert(rel);
        }
    }
    out
}

/// The `[[test]]` target paths Cargo.toml registers, relative to `examples/rust`.
fn registered_test_files(root: &Path) -> Vec<String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("reading Cargo.toml");
    let mut out = Vec::new();
    let mut in_test = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_test = t == "[[test]]";
            continue;
        }
        if in_test {
            if let Some(rest) = t.strip_prefix("path") {
                if let Some(q) = rest.find('"') {
                    if let Some(end) = rest[q + 1..].find('"') {
                        out.push(rest[q + 1..q + 1 + end].to_string());
                    }
                }
            }
        }
    }
    out
}

/// The contracts a registered test target `#[path]`-includes as a module,
/// relative to `examples/rust`.
///
/// `#[path]` shown inside a comment does not count — this file's own header
/// discusses one, and `ECUnit_test.rs` used to carry a comment explaining why
/// it could not use one.
fn natively_included(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for test_rel in registered_test_files(root) {
        let test_path = root.join(&test_rel);
        let src = match fs::read_to_string(&test_path) {
            Ok(s) => s,
            Err(e) => panic!("Cargo.toml registers {test_rel}, which cannot be read: {e}"),
        };
        let code = strip_comments(&src);
        for inc in path_mod_includes(&code) {
            let resolved = test_path.parent().unwrap().join(&inc);
            let rel = resolved
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| inc.clone());
            out.insert(rel);
        }
    }
    out
}

/// Every `#[path = "X"] mod` in comment-stripped Rust source.
fn path_mod_includes(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = code[from..].find("#[path") {
        let start = from + rel;
        from = start + 1;
        let rest = &code[start..];
        let open = match rest.find('"') {
            Some(i) => i,
            None => continue,
        };
        let close = match rest[open + 1..].find('"') {
            Some(i) => open + 1 + i,
            None => continue,
        };
        let value = rest[open + 1..close].to_string();
        let after = &rest[close + 1..];
        let after = after.trim_start_matches([']', ' ', '\n', '\t', '\r']);
        // Only a `#[path]` attached to a `mod` item pulls the file in.
        if after.starts_with("mod ") || after.starts_with("pub mod ") {
            out.push(value);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The ratchet
// ---------------------------------------------------------------------------

#[test]
fn excluded_contracts_are_exactly_the_justified_set() {
    let root = examples_root();
    let universe = universe(&root);
    let included = natively_included(&root);
    let got: BTreeSet<String> = universe.difference(&included).cloned().collect();
    let want: BTreeSet<String> = EXCLUDED.iter().map(|s| s.to_string()).collect();

    assert_eq!(
        got,
        want,
        "\n\nthe set of byte-builtin .runar.rs contracts excluded from native Rust \
         compilation changed.\n\ngot  ({}): {:?}\nwant ({}): {:?}\n\n\
         A .runar.rs contract is supposed to compile BOTH as Rúnar and as Rust — that is \
         what makes `cargo test` check its business logic instead of only its syntax. An \
         exclusion gives up half of that, so the set is pinned rather than bounded.\n\n\
         Adding one: write the reason at the top of the contract file, starting with {:?}, \
         and add it to EXCLUDED in the same commit. \"It did not compile\" is not a reason; \
         the compiler error, and why the contract cannot be written in Rust without \
         weakening what it tests, is.\n\n\
         Removing one: wire the contract into a `[[test]]` target with a `#[path]` module \
         include and delete it from EXCLUDED. Make sure it is fixed rather than deleted — \
         the fix is the point.\n",
        got.len(),
        got,
        want.len(),
        want,
        REASON_MARKER
    );
}

#[test]
fn every_exclusion_carries_a_written_reason() {
    let root = examples_root();
    for rel in EXCLUDED {
        let path = root.join(rel);
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{rel} is listed as excluded but cannot be read: {e}"));

        let idx = src.find(REASON_MARKER).unwrap_or_else(|| {
            panic!(
                "{rel} is excluded from native Rust compilation with no {REASON_MARKER:?} \
                 header. An exclusion without a written reason is how a gap like this \
                 survives: nothing told anyone the contract had never been run."
            )
        });

        // The reason must precede the contract itself, so it is the first thing
        // a reader of the file sees rather than a footnote.
        if let Some(decl) = src.find("#[runar::") {
            assert!(
                idx < decl,
                "{rel} has its {REASON_MARKER:?} header AFTER the contract declaration"
            );
        }

        let reason = &src[idx..src.find("#[runar::").unwrap_or(src.len())];
        let lines = reason.lines().count();
        assert!(
            lines >= 8,
            "{rel} has a {lines}-line reason block; that is a label, not a justification. \
             Name the compiler error and why the contract cannot be written in Rust without \
             weakening what it tests."
        );
    }
}

// ---------------------------------------------------------------------------
// Non-vacuity
// ---------------------------------------------------------------------------

/// The universe is derived by scanning. A derivation that returned nothing
/// would make the set assertion above pass against an empty expectation while
/// checking nothing at all.
#[test]
fn the_universe_is_not_empty() {
    let root = examples_root();
    let u = universe(&root);
    assert_eq!(
        u.len(),
        7,
        "the number of .runar.rs contracts calling one of the eight byte builtins moved \
         from 7 to {}. That is fine — but check that the scan is still finding calls and \
         not, say, matching nothing because a builtin was renamed: {:?}",
        u.len(),
        u
    );
    // And the two halves must actually be distinct, or `difference` is the
    // identity and the ratchet degenerates into "the universe is EXCLUDED".
    let included = natively_included(&root);
    assert!(
        u.iter().any(|c| included.contains(c)),
        "no contract in the universe is natively included — the include scan found \
         nothing, so every contract would read as excluded"
    );
}

/// The scanner, run over a tree whose answer is known.
///
/// Both halves are wrong in specific, already-observed ways if written
/// carelessly: `data.len()` is a Rust method and not the Rúnar builtin, a
/// builtin named in a doc comment is prose, and a `#[path]` inside a comment
/// includes nothing.
#[test]
fn the_scanner_answers_a_known_tree() {
    let dir = std::env::temp_dir().join(format!("runar-exclusion-scan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);

    let write = |rel: &str, body: &str| {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    };

    // Calls the builtin: in the universe.
    write(
        "calls/Calls.runar.rs",
        "use runar::prelude::*;\npub fn f(d: Vec<u8>) { assert!(len(&d) > 0); }\n",
    );
    // Calls a DIFFERENT builtin, and is wired up: in the universe, not excluded.
    write(
        "wired/Wired.runar.rs",
        "use runar::prelude::*;\npub fn f(d: Vec<u8>) -> Vec<u8> { split(&d, 1) }\n",
    );
    write("wired/Wired_test.rs", "#[path = \"Wired.runar.rs\"]\nmod contract;\n");
    // Mentions builtins only in prose, and uses the Rust METHOD `len`.
    write(
        "prose/Prose.runar.rs",
        "/// Exercises len(), split() and reverse_bytes() on chain.\n\
         /* left(x, 1) and right(x, 1) too */\n\
         use runar::prelude::*;\n\
         pub fn f(d: Vec<u8>) -> usize { d.len() }\n\
         pub fn g() -> &'static str { \"len(\" }\n",
    );
    // A contract whose only `#[path]` reference is inside a comment.
    write("commented/Commented.runar.rs", "use runar::prelude::*;\npub fn f(d: Vec<u8>) { left(&d, 1); }\n");
    write(
        "commented/Commented_test.rs",
        "// We cannot use #[path = \"Commented.runar.rs\"] mod contract; here.\n#[test]\nfn t() {}\n",
    );
    // A `#[path]` on something that is not a module include.
    write("attrpath/AttrPath.runar.rs", "use runar::prelude::*;\npub fn f(d: Vec<u8>) { right(&d, 1); }\n");
    write(
        "attrpath/AttrPath_test.rs",
        "#[path = \"AttrPath.runar.rs\"]\nfn not_a_mod() {}\n",
    );

    fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"x\"\n\n\
         [[test]]\nname = \"wired\"\npath = \"wired/Wired_test.rs\"\n\n\
         [[test]]\nname = \"commented\"\npath = \"commented/Commented_test.rs\"\n\n\
         [[test]]\nname = \"attrpath\"\npath = \"attrpath/AttrPath_test.rs\"\n\n\
         [dependencies]\npath = \"not-a-test-target\"\n",
    )
    .unwrap();

    let u = universe(&dir);
    let want_universe: BTreeSet<String> = [
        "attrpath/AttrPath.runar.rs",
        "calls/Calls.runar.rs",
        "commented/Commented.runar.rs",
        "wired/Wired.runar.rs",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(u, want_universe, "universe scan");

    let inc = natively_included(&dir);
    let want_included: BTreeSet<String> = ["wired/Wired.runar.rs".to_string()].into_iter().collect();
    assert_eq!(inc, want_included, "native-include scan");

    let excluded: BTreeSet<String> = u.difference(&inc).cloned().collect();
    let want_excluded: BTreeSet<String> = [
        "attrpath/AttrPath.runar.rs",
        "calls/Calls.runar.rs",
        "commented/Commented.runar.rs",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(excluded, want_excluded, "excluded set");

    fs::remove_dir_all(&dir).unwrap();
}
