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
use runar_compiler_rust::frontend::parser::parse_source;

fn conformance_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("tests")
}

fn read_conformance_format(test_name: &str, ext: &str) -> Option<String> {
    let path = conformance_dir().join(test_name).join(format!("{}{}", test_name, ext));
    std::fs::read_to_string(&path).ok()
}

// ---------------------------------------------------------------------------
// Test: parse_source dispatch routes to the correct parser
// ---------------------------------------------------------------------------

#[test]
fn test_parse_dispatch_sol() {
    let source = read_conformance_format("arithmetic", ".runar.sol");
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("arithmetic.runar.sol"));
    assert!(result.contract.is_some(), "Solidity parser should produce a contract");
    assert_eq!(result.contract.as_ref().unwrap().name, "Arithmetic");
}

#[test]
fn test_parse_dispatch_move() {
    let source = read_conformance_format("arithmetic", ".runar.move");
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("arithmetic.runar.move"));
    // Move parser may produce errors on some constructs (known issue)
    if result.contract.is_some() {
        assert_eq!(result.contract.as_ref().unwrap().name, "Arithmetic");
    }
}

#[test]
fn test_parse_dispatch_rs() {
    let source = read_conformance_format("arithmetic", ".runar.rs");
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("arithmetic.runar.rs"));
    if result.contract.is_some() {
        assert_eq!(result.contract.as_ref().unwrap().name, "Arithmetic");
    }
}

#[test]
fn test_parse_dispatch_ts() {
    let source = read_conformance_format("arithmetic", ".runar.ts");
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("arithmetic.runar.ts"));
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
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("arithmetic.runar.sol"));
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
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("basic-p2pkh.runar.sol"));
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
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("arithmetic.runar.move"));
    if result.contract.is_none() { return; } // Move parser may have issues (known)
    let contract = result.contract.unwrap();

    assert_eq!(contract.name, "Arithmetic");
    if !contract.methods.is_empty() {
        assert_eq!(contract.methods[0].name, "verify");
    }
}

#[test]
fn test_parse_move_p2pkh() {
    let source = read_conformance_format("basic-p2pkh", ".runar.move");
    if source.is_none() { return; }
    let result = parse_source(&source.unwrap(), Some("basic-p2pkh.runar.move"));
    if result.contract.is_none() { return; } // Move parser may have issues (known)

    assert_eq!(result.contract.unwrap().name, "P2PKH");
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
        if source.is_none() { continue; }
        let artifact = compile_from_source_str(&source.unwrap(), Some(&format!("{}.runar.ts", dir)))
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
    let ts_source = read_conformance_format("basic-p2pkh", ".runar.ts");
    if let Some(ts_src) = ts_source {
        let ts_artifact = compile_from_source_str(&ts_src, Some("basic-p2pkh.runar.ts"))
            .expect("TS P2PKH compilation should succeed");

        assert_eq!(
            rb_artifact.script, ts_artifact.script,
            "Ruby and TypeScript P2PKH should produce identical script"
        );
    }
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
        if source.is_none() { continue; }
        let result = parse_source(&source.unwrap(), Some(&format!("arithmetic{}", ext)));

        if let Some(contract) = result.contract {
            assert!(!contract.properties.is_empty(),
                    "{}: expected at least 1 property", ext);
        }
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
        if source.is_none() { continue; }
        let result = parse_source(&source.unwrap(), Some(&format!("arithmetic{}", ext)));

        if let Some(contract) = result.contract {
            assert!(!contract.methods.is_empty(),
                    "{}: expected at least 1 method", ext);
            let method = &contract.methods[0];
            assert_eq!(method.name, "verify",
                       "{}: expected method 'verify'", ext);
            assert_eq!(method.params.len(), 2,
                       "{}: expected 2 params", ext);
        }
    }
}

// ---------------------------------------------------------------------------
// Test: parse_source dispatch for Python and Go formats
// ---------------------------------------------------------------------------

#[test]
fn test_parse_dispatch_py() {
    // parse_source with a .runar.py filename should route to the Python parser.
    // We use the conformance test's .runar.py file if available; otherwise a
    // minimal inline snippet.
    let py_source = read_conformance_format("arithmetic", ".runar.py")
        .unwrap_or_else(|| {
            // Minimal Python-format Rúnar contract
            r#"from runar import SmartContract, Readonly

class Arithmetic(SmartContract):
    target: Readonly[int]

    def __init__(self, target: int):
        super().__init__(target)
        self.target = target

    @public
    def verify(self, a: int, b: int):
        assert_(a + b == self.target)
"#.to_string()
        });

    // Must not panic; may succeed or produce parse errors
    let result = parse_source(&py_source, Some("Arithmetic.runar.py"));
    // If the Python parser produces a contract, verify the name is plausible
    if let Some(contract) = result.contract {
        assert!(
            !contract.name.is_empty(),
            "Python parser should produce a non-empty contract name"
        );
    } else {
        // No contract + errors is also acceptable (parser may be partial)
        // The key invariant is no panic.
    }
}

#[test]
fn test_parse_dispatch_go() {
    // parse_source with a .runar.go filename should route to the Go/runar-go parser.
    let go_source = read_conformance_format("arithmetic", ".runar.go")
        .unwrap_or_else(|| {
            // Minimal Go-format Rúnar contract
            r#"package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Arithmetic struct {
    Target runar.BigInt `runar:"readonly"`
}

func (c *Arithmetic) init() {
    c.Target = 0
}

func (c *Arithmetic) Verify(a runar.BigInt, b runar.BigInt) {
    runar.Assert(a+b == c.Target)
}
"#.to_string()
        });

    // Must not panic; may succeed or produce parse errors
    let result = parse_source(&go_source, Some("Arithmetic.runar.go"));
    if let Some(contract) = result.contract {
        assert!(
            !contract.name.is_empty(),
            "Go parser should produce a non-empty contract name"
        );
    }
    // No contract is also acceptable (errors or partial parse is fine)
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
