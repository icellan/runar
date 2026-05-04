//! Multi-format parsing tests for the Rust compiler.
//!
//! These tests verify that `parse_source` correctly dispatches to the
//! appropriate parser based on file extension, and that each format parser
//! produces a valid AST for the conformance test contracts.
//!
//! Full end-to-end compilation for non-.runar.ts formats requires parser
//! maturation (type mapping, constructor synthesis, etc.). These tests
//! focus on parse-level correctness and dispatch routing.

use runar_compiler_rust::compile_from_source_str;
use runar_compiler_rust::frontend::ast::Visibility;
use runar_compiler_rust::frontend::parser::parse_source;

fn conformance_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("tests")
}

/// Resolve a conformance fixture's source for the given extension via its
/// `source.json` manifest. Earlier versions of this helper looked for
/// `<test>/<test>.runar.<ext>` directly, which never existed — the conformance
/// suite stores sources under `examples/...` and points at them via
/// `source.json`. The buggy resolver caused every multi-format test in this
/// file to silently SKIP (matching the parser_format_tests.rs convention).
/// `expect`-ing here is correct because every checked-in fixture has every
/// `.runar.{ts,sol,move,go,rs,py,zig,rb,java}` entry populated; if a fixture
/// drops a format, the test must FAIL LOUDLY rather than no-op.
fn read_conformance_format(test_name: &str, ext: &str) -> String {
    let cfg_path = conformance_dir().join(test_name).join("source.json");
    let raw = std::fs::read_to_string(&cfg_path)
        .unwrap_or_else(|e| panic!("missing conformance source.json {:?}: {}", cfg_path, e));
    let cfg: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON {:?}: {}", cfg_path, e));
    let rel = cfg
        .get("sources")
        .and_then(|s| s.get(ext))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("source.json {:?} missing sources[{}] entry", cfg_path, ext));
    let resolved = cfg_path.parent().unwrap().join(rel);
    std::fs::read_to_string(&resolved)
        .unwrap_or_else(|e| panic!("failed to read fixture {:?}: {}", resolved, e))
}

// ---------------------------------------------------------------------------
// Test: parse_source dispatch routes to the correct parser
// ---------------------------------------------------------------------------

#[test]
fn test_parse_dispatch_sol() {
    let source = read_conformance_format("arithmetic", ".runar.sol");
    let result = parse_source(&source, Some("arithmetic.runar.sol"));
    assert!(result.contract.is_some(), "Solidity parser should produce a contract");
    assert_eq!(result.contract.as_ref().unwrap().name, "Arithmetic");
}

#[test]
fn test_parse_dispatch_move() {
    let source = read_conformance_format("arithmetic", ".runar.move");
    let result = parse_source(&source, Some("arithmetic.runar.move"));
    // Move parser must produce a contract for the conformance fixture.
    assert!(
        result.contract.is_some(),
        "Move parser should produce a contract for arithmetic.runar.move; errors: {:?}",
        result.errors
    );
    assert_eq!(result.contract.as_ref().unwrap().name, "Arithmetic");
}

#[test]
fn test_parse_dispatch_rs() {
    let source = read_conformance_format("arithmetic", ".runar.rs");
    let result = parse_source(&source, Some("arithmetic.runar.rs"));
    assert!(
        result.contract.is_some(),
        "Rust-DSL parser should produce a contract; errors: {:?}",
        result.errors
    );
    assert_eq!(result.contract.as_ref().unwrap().name, "Arithmetic");
}

#[test]
fn test_parse_dispatch_ts() {
    let source = read_conformance_format("arithmetic", ".runar.ts");
    let result = parse_source(&source, Some("arithmetic.runar.ts"));
    assert!(result.errors.is_empty(), "TS parser should succeed: {:?}", result.errors);
    assert!(result.contract.is_some());
    assert_eq!(result.contract.as_ref().unwrap().name, "Arithmetic");
}

// ---------------------------------------------------------------------------
// Test: Solidity parser produces correct AST structure
// ---------------------------------------------------------------------------

#[test]
fn test_parse_sol_arithmetic_structure() {
    let source = read_conformance_format("arithmetic", ".runar.sol");
    let result = parse_source(&source, Some("arithmetic.runar.sol"));
    let contract = result.contract.expect("should parse contract");

    assert_eq!(contract.name, "Arithmetic");
    // Solidity parser produces properties (may include constructor-synthesized extras)
    assert!(!contract.properties.is_empty(), "expected at least 1 property");
    assert!(!contract.methods.is_empty(), "expected at least 1 method");
    // The first user-defined method should be 'verify'
    let has_verify = contract.methods.iter().any(|m| m.name == "verify");
    assert!(has_verify, "expected method 'verify'");
}

#[test]
fn test_parse_sol_p2pkh() {
    let source = read_conformance_format("basic-p2pkh", ".runar.sol");
    let result = parse_source(&source, Some("basic-p2pkh.runar.sol"));
    let contract = result.contract.expect("should parse contract");

    assert_eq!(contract.name, "P2PKH");
    assert_eq!(contract.parent_class, "SmartContract");
}

// ---------------------------------------------------------------------------
// Test: Move parser produces correct AST structure
// ---------------------------------------------------------------------------

#[test]
fn test_parse_move_arithmetic_structure() {
    let source = read_conformance_format("arithmetic", ".runar.move");
    let result = parse_source(&source, Some("arithmetic.runar.move"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Move parser produced no contract for arithmetic.runar.move; errors: {:?}",
            result.errors
        )
    });

    assert_eq!(contract.name, "Arithmetic");
    assert!(!contract.methods.is_empty(), "expected at least 1 method");
    assert_eq!(contract.methods[0].name, "verify");
}

#[test]
fn test_parse_move_p2pkh() {
    let source = read_conformance_format("basic-p2pkh", ".runar.move");
    let result = parse_source(&source, Some("basic-p2pkh.runar.move"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Move parser produced no contract for basic-p2pkh.runar.move; errors: {:?}",
            result.errors
        )
    });

    assert_eq!(contract.name, "P2PKH");
}

// ---------------------------------------------------------------------------
// Test: .runar.ts format compiles end-to-end via parse_source dispatch
// ---------------------------------------------------------------------------

#[test]
fn test_ts_end_to_end_all_conformance() {
    let test_dirs = [
        "arithmetic", "basic-p2pkh", "boolean-logic",
        "bounded-loop", "if-else", "multi-method", "stateful",
    ];

    for dir in &test_dirs {
        let source = read_conformance_format(dir, ".runar.ts");
        let artifact = compile_from_source_str(&source, Some(&format!("{}.runar.ts", dir)))
            .unwrap_or_else(|e| panic!("{}: compilation failed: {}", dir, e));

        assert!(!artifact.script.is_empty(), "{}: empty script hex", dir);
        assert!(!artifact.asm.is_empty(), "{}: empty ASM", dir);
        assert!(!artifact.contract_name.is_empty(), "{}: empty contract name", dir);
    }
}

// ---------------------------------------------------------------------------
// Test: Ruby parser dispatch
// ---------------------------------------------------------------------------

#[test]
fn test_parse_dispatch_ruby() {
    let source = r#"
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
"#;
    let result = parse_source(source, Some("P2PKH.runar.rb"));
    assert!(result.errors.is_empty(), "Ruby parser errors: {:?}", result.errors);
    assert!(result.contract.is_some(), "Ruby parser should produce a contract");
    let contract = result.contract.unwrap();
    assert_eq!(contract.name, "P2PKH");
    assert_eq!(contract.parent_class, "SmartContract");
}

// ---------------------------------------------------------------------------
// Test: Ruby parser produces correct AST structure
// ---------------------------------------------------------------------------

#[test]
fn test_parse_ruby_p2pkh_structure() {
    let source = r#"
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
"#;

    let result = parse_source(source, Some("P2PKH.runar.rb"));
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    let contract = result.contract.expect("should parse contract");

    assert_eq!(contract.name, "P2PKH");
    assert_eq!(contract.parent_class, "SmartContract");
    assert_eq!(contract.properties.len(), 1);
    assert_eq!(contract.properties[0].name, "pubKeyHash");
    assert!(contract.properties[0].readonly);

    assert_eq!(contract.methods.len(), 1);
    assert_eq!(contract.methods[0].name, "unlock");
    assert_eq!(contract.methods[0].visibility, Visibility::Public);
    assert_eq!(contract.methods[0].params.len(), 2);
    assert_eq!(contract.methods[0].params[0].name, "sig");
    assert_eq!(contract.methods[0].params[1].name, "pubKey");
}

// ---------------------------------------------------------------------------
// Test: Ruby P2PKH compiles end-to-end and produces same script as TS
// ---------------------------------------------------------------------------

#[test]
fn test_ruby_p2pkh_end_to_end() {
    let rb_source = r#"
require 'runar'

class P2PKH < Runar::SmartContract
  prop :pub_key_hash, Addr

  def initialize(pub_key_hash)
    super(pub_key_hash)
    @pub_key_hash = pub_key_hash
  end

  runar_public sig: Sig, pub_key: PubKey
  def unlock(sig, pub_key)
    assert hash160(pub_key) == @pub_key_hash
    assert check_sig(sig, pub_key)
  end
end
"#;

    let rb_artifact = compile_from_source_str(rb_source, Some("P2PKH.runar.rb"))
        .expect("Ruby P2PKH compilation should succeed");

    assert!(!rb_artifact.script.is_empty(), "Ruby script hex should not be empty");
    assert!(!rb_artifact.asm.is_empty(), "Ruby ASM should not be empty");
    assert_eq!(rb_artifact.contract_name, "P2PKH");

    // Compare with TypeScript compilation
    let ts_src = read_conformance_format("basic-p2pkh", ".runar.ts");
    let ts_artifact = compile_from_source_str(&ts_src, Some("basic-p2pkh.runar.ts"))
        .expect("TS P2PKH compilation should succeed");

    assert_eq!(
        rb_artifact.script, ts_artifact.script,
        "Ruby and TypeScript P2PKH should produce identical script"
    );
}

// ---------------------------------------------------------------------------
// Test: Ruby stateful contract compiles end-to-end
// ---------------------------------------------------------------------------

#[test]
fn test_ruby_stateful_end_to_end() {
    let source = r#"
require 'runar'

class Counter < Runar::StatefulSmartContract
  prop :count, Bigint

  def initialize(count)
    super(count)
    @count = count
  end

  runar_public
  def increment
    @count += 1
  end
end
"#;

    let artifact = compile_from_source_str(source, Some("Counter.runar.rb"))
        .expect("Ruby Counter compilation should succeed");

    assert!(!artifact.script.is_empty(), "Ruby Counter script hex should not be empty");
    assert_eq!(artifact.contract_name, "Counter");
}

// ---------------------------------------------------------------------------
// Test: Cross-format property consistency (parse-level)
// ---------------------------------------------------------------------------

#[test]
fn test_cross_format_property_consistency() {
    let formats = [".runar.sol", ".runar.move"];

    for ext in &formats {
        let source = read_conformance_format("arithmetic", ext);
        let result = parse_source(&source, Some(&format!("arithmetic{}", ext)));

        let contract = result.contract.unwrap_or_else(|| {
            panic!(
                "{}: parser produced no contract; errors: {:?}",
                ext, result.errors
            )
        });
        assert!(
            !contract.properties.is_empty(),
            "{}: expected at least 1 property",
            ext
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Cross-format method parameter consistency (parse-level)
// ---------------------------------------------------------------------------

#[test]
fn test_cross_format_method_param_consistency() {
    let formats = [".runar.sol", ".runar.move"];

    for ext in &formats {
        let source = read_conformance_format("arithmetic", ext);
        let result = parse_source(&source, Some(&format!("arithmetic{}", ext)));

        let contract = result.contract.unwrap_or_else(|| {
            panic!(
                "{}: parser produced no contract; errors: {:?}",
                ext, result.errors
            )
        });
        assert!(
            !contract.methods.is_empty(),
            "{}: expected at least 1 method",
            ext
        );
        let method = &contract.methods[0];
        assert_eq!(method.name, "verify", "{}: expected method 'verify'", ext);
        assert_eq!(method.params.len(), 2, "{}: expected 2 params", ext);
    }
}

// ---------------------------------------------------------------------------
// Test: parse_source dispatch for Python and Go formats
// ---------------------------------------------------------------------------

#[test]
fn test_parse_dispatch_py() {
    // parse_source with a .runar.py filename should route to the Python parser
    // and produce the conformance Arithmetic contract.
    let py_source = read_conformance_format("arithmetic", ".runar.py");

    let result = parse_source(&py_source, Some("Arithmetic.runar.py"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Python parser produced no contract for arithmetic.runar.py; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "Arithmetic");
}

#[test]
fn test_parse_dispatch_go() {
    // parse_source with a .runar.go filename should route to the Go DSL parser
    // and produce the conformance Arithmetic contract.
    let go_source = read_conformance_format("arithmetic", ".runar.go");

    let result = parse_source(&go_source, Some("Arithmetic.runar.go"));
    let contract = result.contract.unwrap_or_else(|| {
        panic!(
            "Go parser produced no contract for arithmetic.runar.go; errors: {:?}",
            result.errors
        )
    });
    assert_eq!(contract.name, "Arithmetic");
}

#[test]
fn test_parse_dispatch_unknown_extension() {
    // parse_source with an unrecognized extension should produce errors
    // or an empty result — it must NOT panic.
    let source = "class Foo { }";
    let result = parse_source(source, Some("Contract.runar.xyz"));

    // An unrecognized extension should either produce errors or an empty result.
    let has_contract = result.contract.is_some();
    let has_errors = !result.errors.is_empty();

    assert!(
        !has_contract || has_errors,
        "unrecognized extension should produce errors or no contract; got contract with no errors"
    );
}

#[test]
fn test_ruby_unknown_parent_class() {
    let source = r#"
class Foo < Runar::UnknownBase
  prop :x, Bigint
  def initialize(x)
    super(x)
  end
  runar_public
  def bar
    assert @x > 0
  end
end
"#;
    let result = parse_source(source, Some("Test.runar.rb"));
    assert!(
        result.contract.is_none() || !result.errors.is_empty(),
        "expected errors or no contract for unknown parent class"
    );
}

#[test]
fn test_ruby_missing_prop_type() {
    let source = r#"
class Foo < Runar::SmartContract
  prop :x
  def initialize(x)
    super(x)
  end
  runar_public
  def bar
    assert @x > 0
  end
end
"#;
    let result = parse_source(source, Some("Test.runar.rb"));
    assert!(
        result.contract.is_none() || !result.errors.is_empty(),
        "expected errors or no contract for prop missing type"
    );
}

#[test]
fn test_ruby_missing_method_end() {
    let source = r#"
class Foo < Runar::SmartContract
  prop :x, Bigint
  def initialize(x)
    super(x)
  end
  runar_public
  def bar
    assert @x > 0
"#;
    let result = parse_source(source, Some("Test.runar.rb"));
    assert!(
        result.contract.is_none() || !result.errors.is_empty(),
        "expected errors or no contract for unclosed method"
    );
}

#[test]
fn test_ruby_empty_source() {
    let result = parse_source("", Some("Test.runar.rb"));
    assert!(
        result.contract.is_none() || !result.errors.is_empty(),
        "expected errors or no contract for empty source"
    );
}
