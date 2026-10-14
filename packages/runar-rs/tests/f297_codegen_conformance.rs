//! F-297 — cross-SDK codegen conformance runner, Rust side.
//!
//! `conformance/sdk-codegen/` exists because the Rust generator's own bug
//! (fixed in c00cfe7: the constructor body referenced the bare param name
//! `count` instead of `args.count`, which is only valid *inside* the
//! generated `new(artifact, args: CounterConstructorArgs)` — a Rust-only
//! compile error no SDK's string-pattern test ever ran against a real
//! compiler) was the motivating case for the suite, yet until this file the
//! Rust tier was the one tier with no runner at all. Java
//! (`packages/runar-java/src/test/java/runar/lang/sdk/codegen/CodegenConformanceTest.java`),
//! Ruby (`packages/runar-rb/spec/sdk/codegen_conformance_spec.rb`) and Zig
//! (`packages/runar-zig/src/sdk_codegen_conformance_test.zig`) ship full
//! MANIFEST-shaped runners; Go (`packages/runar-go/sdk_codegen_test.go`)
//! ships a partial one (2 of 5 fixtures, Go-shape-only assertions, but it
//! DOES `go vet`-compile the generated wrapper). None of the four live at
//! `conformance/sdk-codegen/runners/<lang>/` — the MANIFEST/README's
//! documented layout describes a directory that was never actually created
//! for any tier. This runner follows the REAL precedent instead: a test
//! inside the SDK's own test tree (here, `packages/runar-rs/tests/`,
//! alongside `envelope_interop.rs`'s cross-tier-fixture pattern), loading
//! the shared fixtures from `conformance/sdk-codegen/fixtures/`.
//!
//! What this test proves:
//!   - `generate_rust` for all 5 shared fixtures (p2pkh, counter, simple,
//!     stateful-escrow, inscribed) emits every structural element the Rust
//!     generator currently supports (typed constructor-args struct, method
//!     signatures with user params, `*StatefulCallOptions`, `TerminalOutput`,
//!     `prepare_*`/`finalize_*` companions for Sig-bearing methods, including
//!     the escrow's two-signature `finalize_release`).
//!   - All 5 generated wrappers COMPILE (`cargo check`) against the real
//!     `runar-lang` crate as an external dependency aliased `runar` — the
//!     same way `examples/rust/Cargo.toml` consumes it, and the same shape
//!     the generated `use runar::sdk::...` lines assume. This is a real
//!     compiler, not a syntax-only parse: the original c00cfe7 bug was
//!     syntactically valid Rust (a bare identifier is never a parse error)
//!     and would NOT have been caught by a `syn::parse_file` check — only
//!     type/name resolution catches "undefined variable `count`". A revert
//!     of c00cfe7 against this runner reproduces E0425 (see the regression
//!     note in `codegen_rejects_bare_constructor_param_reference` below).
//!
//! What this test does not prove:
//!   - Full MANIFEST compliance. The Rust generator does NOT emit
//!     `from_utxo`/`from_txid`-as-factory-pair parity with Ruby/Java (it has
//!     `from_txid` but no `from_utxo`), does NOT emit `attach_inscription`
//!     (so `inscribed.json`'s delegation requirement is unmet — the
//!     `InscribedHolderContract` wrapper compiles but has no inscription
//!     API), does NOT emit an `OutputSpec` record or expose
//!     `CallOptions.outputs` on `*StatefulCallOptions` (only
//!     satoshis/change_address/change_pub_key/new_state), and does NOT emit
//!     typed state accessors (e.g. a `count()` getter on `CounterContract`).
//!     These are real gaps in the Rust generator relative to its Ruby/Java
//!     peers, not gaps in this runner — fixing them is generator feature
//!     work, out of scope for the runner this file adds, and is called out
//!     here rather than silently passed over.
//!   - Runtime behavior. Like the Ruby/Zig runners (and unlike Go's, which
//!     also runs the generated wrapper end-to-end against a `MockProvider`),
//!     this is a static compile-check only — it does not deploy, call, or
//!     sign anything.
//!   - Anything about the TypeScript or Python generators (separate items).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use runar_lang::sdk::{generate_rust, RunarArtifact};

fn repo_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn fixtures_dir() -> PathBuf {
    repo_root().join("conformance").join("sdk-codegen").join("fixtures")
}

fn load_fixture(name: &str) -> RunarArtifact {
    let path = fixtures_dir().join(name);
    let data = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse fixture {}: {}", name, e))
}

fn assert_contains(src: &str, needle: &str, label: &str) {
    assert!(
        src.contains(needle),
        "{label}: generated Rust is missing `{needle}`\n--- generated ---\n{src}"
    );
}

fn assert_not_contains(src: &str, needle: &str, label: &str) {
    assert!(
        !src.contains(needle),
        "{label}: generated Rust unexpectedly contains `{needle}`\n--- generated ---\n{src}"
    );
}

// ---------------------------------------------------------------------------
// Structural assertions (per MANIFEST.md, scoped to what the Rust generator
// actually emits today — see the module doc's "does not prove" section).
// ---------------------------------------------------------------------------

#[test]
fn p2pkh_fixture_has_required_structural_elements() {
    let artifact = load_fixture("p2pkh.json");
    let src = generate_rust(&artifact);

    assert_contains(&src, "pub struct P2PKHConstructorArgs", "p2pkh");
    assert_contains(&src, "pub struct P2PKHContract", "p2pkh");
    assert_contains(&src, "pub fn from_txid(", "p2pkh");
    assert_contains(&src, "pub fn connect(", "p2pkh");
    assert_contains(&src, "pub fn get_locking_script(", "p2pkh");
    assert_contains(&src, "pub fn deploy(", "p2pkh");
    assert_contains(&src, "pub fn unlock(", "p2pkh");
    assert_contains(&src, "pub fn prepare_unlock(", "p2pkh");
    assert_contains(&src, "pub fn finalize_unlock(", "p2pkh");
    assert_contains(&src, "pub struct TerminalOutput", "p2pkh");
    assert_not_contains(&src, "StatefulCallOptions", "p2pkh (stateless contract)");
    assert!(!src.contains("{{"), "p2pkh: unrendered Mustache tag:\n{src}");
}

#[test]
fn counter_fixture_has_required_structural_elements() {
    let artifact = load_fixture("counter.json");
    let src = generate_rust(&artifact);

    assert_contains(&src, "pub struct CounterConstructorArgs", "counter");
    assert_contains(&src, "pub count:", "counter");
    assert_contains(&src, "pub struct CounterStatefulCallOptions", "counter");
    assert_contains(&src, "pub satoshis:", "counter");
    assert_contains(&src, "pub change_address:", "counter");
    assert_contains(&src, "pub change_pub_key:", "counter");
    assert_contains(&src, "pub new_state:", "counter");
    assert_contains(&src, "pub struct TerminalOutput", "counter");
    assert_contains(&src, "pub fn increment(", "counter");
    assert_contains(&src, "pub fn reset(", "counter");
    assert_contains(&src, "pub struct CounterContract", "counter");
    assert!(!src.contains("{{"), "counter: unrendered Mustache tag:\n{src}");
}

#[test]
fn simple_fixture_has_required_structural_elements() {
    let artifact = load_fixture("simple.json");
    let src = generate_rust(&artifact);

    assert_not_contains(&src, "SimpleConstructorArgs", "simple (no ctor params)");
    assert_contains(&src, "pub struct SimpleContract", "simple");
    assert_contains(&src, "pub fn new(artifact: RunarArtifact) -> Self", "simple");
    assert_contains(&src, "pub fn execute(", "simple");
    assert!(!src.contains("{{"), "simple: unrendered Mustache tag:\n{src}");
}

#[test]
fn stateful_escrow_fixture_has_required_structural_elements() {
    let artifact = load_fixture("stateful-escrow.json");
    let src = generate_rust(&artifact);

    assert_contains(&src, "pub struct EscrowConstructorArgs", "escrow");
    assert_contains(&src, "pub buyer:", "escrow");
    assert_contains(&src, "pub seller:", "escrow");
    assert_contains(&src, "pub amount:", "escrow");
    assert_contains(&src, "pub struct EscrowStatefulCallOptions", "escrow");
    assert_contains(&src, "pub struct TerminalOutput", "escrow");

    // claim: non-terminal, single Sig (buyerSig) -> prepare/finalize.
    assert_contains(&src, "pub fn claim(", "escrow");
    assert_contains(&src, "pub fn prepare_claim(", "escrow");
    assert_contains(&src, "pub fn finalize_claim(", "escrow");
    assert_contains(&src, "buyer_sig: String", "escrow finalize_claim signer param");

    // release: terminal, two Sig params (buyerSig, sellerSig) in ABI order.
    assert_contains(&src, "pub fn release(", "escrow");
    assert_contains(&src, "pub fn prepare_release(", "escrow");
    assert_contains(&src, "pub fn finalize_release(", "escrow");
    let finalize_release_idx = src.find("pub fn finalize_release(").expect("finalize_release present");
    let finalize_release_body = &src[finalize_release_idx..];
    let buyer_idx = finalize_release_body.find("buyer_sig: String").expect("buyer_sig param");
    let seller_idx = finalize_release_body.find("seller_sig: String").expect("seller_sig param");
    assert!(
        buyer_idx < seller_idx,
        "finalize_release must take buyer_sig before seller_sig (ABI order):\n{finalize_release_body}"
    );
    assert!(!src.contains("{{"), "escrow: unrendered Mustache tag:\n{src}");
}

#[test]
fn inscribed_fixture_compiles_despite_missing_attach_inscription() {
    // MANIFEST requires an `attach_inscription`/`attachInscription` delegation
    // for this fixture. The Rust generator does not emit one (no
    // `{{#hasInscription}}`-equivalent section in RUST_TEMPLATE) — documented
    // in this module's doc comment rather than faked here. What IS asserted
    // is that the rest of the wrapper (constructor args, transfer +
    // prepare/finalize) still renders correctly for a fixture shaped like
    // every other stateless + Sig-param contract.
    let artifact = load_fixture("inscribed.json");
    let src = generate_rust(&artifact);

    assert_contains(&src, "pub struct InscribedHolderConstructorArgs", "inscribed");
    assert_contains(&src, "pub owner:", "inscribed");
    assert_contains(&src, "pub struct InscribedHolderContract", "inscribed");
    assert_contains(&src, "pub fn transfer(", "inscribed");
    assert_contains(&src, "pub fn prepare_transfer(", "inscribed");
    assert_contains(&src, "pub fn finalize_transfer(", "inscribed");
    assert_not_contains(&src, "attach_inscription", "inscribed (Rust generator gap, documented above)");
    assert!(!src.contains("{{"), "inscribed: unrendered Mustache tag:\n{src}");
}

// ---------------------------------------------------------------------------
// Compile-check: the part a structural assertion cannot cover. Writes all 5
// generated wrappers into one throwaway crate that depends on this checkout's
// `runar-lang` (aliased `runar`, matching `examples/rust/Cargo.toml` and the
// generated `use runar::sdk::...` lines) and runs a single `cargo check`.
// ---------------------------------------------------------------------------

/// Scratch root for the compile-check crate, nested under this crate's own
/// `target/` (gitignored) rather than the shared OS temp dir, and under its
/// own `CARGO_TARGET_DIR` rather than this crate's main target dir — a
/// sibling `cargo check` invoked from inside a running `cargo test` process
/// must not contend for the same target-directory lock mid-build.
fn scratch_root() -> PathBuf {
    repo_root()
        .join("packages")
        .join("runar-rs")
        .join("target")
        .join("f297-codegen-check")
}

/// `slot` must be unique per concurrently-running test: `cargo test` runs
/// test functions on separate threads by default, and two tests sharing one
/// `crate_dir` race the `remove_dir_all` + rewrite below against whichever
/// other test's `cargo check` subprocess currently has that directory as its
/// working directory (observed as "couldn't get the current directory of
/// the process" when the directory vanished mid-check).
fn write_crate(slot: &str, files: &HashMap<&str, String>) -> PathBuf {
    let root = scratch_root();
    let crate_dir = root.join(format!("crate-{slot}"));
    let _ = fs::remove_dir_all(&crate_dir);
    fs::create_dir_all(crate_dir.join("src")).expect("create crate dir");

    let runar_rs_path = repo_root().join("packages").join("runar-rs");
    let cargo_toml = format!(
        "[package]\nname = \"f297-codegen-check\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\nrunar = {{ package = \"runar-lang\", path = {:?} }}\nnum-bigint = \"0.4\"\n",
        runar_rs_path.to_str().expect("utf8 path")
    );
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml).expect("write Cargo.toml");

    let lock_src = runar_rs_path.join("Cargo.lock");
    if lock_src.exists() {
        let _ = fs::copy(&lock_src, crate_dir.join("Cargo.lock"));
    }

    let mut lib_rs = String::new();
    for module_name in files.keys() {
        lib_rs.push_str(&format!("pub mod {module_name};\n"));
    }
    fs::write(crate_dir.join("src").join("lib.rs"), lib_rs).expect("write lib.rs");

    for (module_name, src) in files {
        fs::write(crate_dir.join("src").join(format!("{module_name}.rs")), src)
            .expect("write generated module");
    }

    crate_dir
}

fn cargo_check(crate_dir: &Path) -> std::process::Output {
    let target_dir = scratch_root().join("target");
    Command::new(env!("CARGO"))
        .arg("check")
        .arg("--offline")
        .current_dir(crate_dir)
        .env("CARGO_TARGET_DIR", &target_dir)
        .output()
        .expect("spawn cargo check")
}

#[test]
fn all_five_generated_wrappers_compile_against_runar_lang() {
    let mut files = HashMap::new();
    files.insert("p2pkh", generate_rust(&load_fixture("p2pkh.json")));
    files.insert("counter", generate_rust(&load_fixture("counter.json")));
    files.insert("simple", generate_rust(&load_fixture("simple.json")));
    files.insert("escrow", generate_rust(&load_fixture("stateful-escrow.json")));
    files.insert("inscribed", generate_rust(&load_fixture("inscribed.json")));

    let crate_dir = write_crate("full", &files);
    let output = cargo_check(&crate_dir);
    assert!(
        output.status.success(),
        "cargo check failed for the generated wrappers:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Regression proof that the compile-check above has teeth: reverting the
/// c00cfe7 fix (bare `count` instead of `args.count` in the constructor
/// body) reproduces an E0425 "cannot find value" compile error, which a
/// syntax-only check (the Ruby runner's `RubyVM::InstructionSequence.compile`
/// equivalent) would NOT catch — a bare identifier reference is syntactically
/// valid Rust. This test does not revert the real generator; it hand-builds
/// the pre-fix constructor body shape against the current template preamble
/// to demonstrate the error class the real compile-check above guards
/// against staying caught.
#[test]
fn cargo_check_rejects_bare_constructor_param_reference() {
    let artifact = load_fixture("counter.json");
    let good = generate_rust(&artifact);
    assert_contains(&good, "args.count", "counter (post c00cfe7 fix)");

    // Reproduce the pre-c00cfe7 shape: drop the `args.` prefix so the
    // constructor body references an out-of-scope bare identifier.
    let broken = good.replace("SdkValue::BigInt(args.count)", "SdkValue::BigInt(count)");
    assert!(broken != good, "replacement must have changed the source");

    let mut files = HashMap::new();
    files.insert("counter_broken", broken);
    let crate_dir = write_crate("broken", &files);
    let output = cargo_check(&crate_dir);
    assert!(
        !output.status.success(),
        "expected cargo check to reject the bare `count` reference, but it succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("E0425") || stderr.contains("cannot find value"),
        "expected an E0425 'cannot find value' error, got:\n{stderr}"
    );
}
