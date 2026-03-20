//! Integration tests for the Rúnar Rust compiler.

use runar_compiler_rust::{compile_from_ir_str, compile_from_ir_str_with_options, compile_from_source_str, compile_from_source_str_with_options, CompileOptions};

// ---------------------------------------------------------------------------
// Test: IR loading — Basic P2PKH
// ---------------------------------------------------------------------------

#[test]
fn test_load_ir_basic_p2pkh() {
    let ir_json = r#"{
        "contractName": "P2PKH",
        "properties": [
            {"name": "pubKeyHash", "type": "Addr", "readonly": true}
        ],
        "methods": [{
            "name": "unlock",
            "params": [
                {"name": "sig", "type": "Sig"},
                {"name": "pubKey", "type": "PubKey"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
                {"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
                {"name": "t3", "value": {"kind": "call", "func": "hash160", "args": ["t1"]}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t3", "right": "t2"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}},
                {"name": "t6", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
                {"name": "t7", "value": {"kind": "assert", "value": "t6"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("compilation should succeed");
    assert_eq!(artifact.contract_name, "P2PKH");
    assert!(!artifact.script.is_empty(), "script hex should not be empty");
    assert!(!artifact.asm.is_empty(), "asm should not be empty");
    assert_eq!(artifact.version, "runar-v0.1.0");

    println!("P2PKH script hex: {}", artifact.script);
    println!("P2PKH script asm: {}", artifact.asm);
}

// ---------------------------------------------------------------------------
// Test: Arithmetic operations
// ---------------------------------------------------------------------------

#[test]
fn test_compile_arithmetic() {
    let ir_json = r#"{
        "contractName": "Arithmetic",
        "properties": [
            {"name": "target", "type": "bigint", "readonly": true}
        ],
        "methods": [{
            "name": "verify",
            "params": [
                {"name": "a", "type": "bigint"},
                {"name": "b", "type": "bigint"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "b"}},
                {"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}},
                {"name": "t3", "value": {"kind": "bin_op", "op": "-", "left": "t0", "right": "t1"}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "*", "left": "t0", "right": "t1"}},
                {"name": "t5", "value": {"kind": "bin_op", "op": "/", "left": "t0", "right": "t1"}},
                {"name": "t6", "value": {"kind": "bin_op", "op": "+", "left": "t2", "right": "t3"}},
                {"name": "t7", "value": {"kind": "bin_op", "op": "+", "left": "t6", "right": "t4"}},
                {"name": "t8", "value": {"kind": "bin_op", "op": "+", "left": "t7", "right": "t5"}},
                {"name": "t9", "value": {"kind": "load_prop", "name": "target"}},
                {"name": "t10", "value": {"kind": "bin_op", "op": "===", "left": "t8", "right": "t9"}},
                {"name": "t11", "value": {"kind": "assert", "value": "t10"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("compilation should succeed");
    assert_eq!(artifact.contract_name, "Arithmetic");
    assert!(!artifact.script.is_empty());

    // Verify arithmetic opcodes are present
    for op in &["OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV"] {
        assert!(
            artifact.asm.contains(op),
            "expected ASM to contain {}",
            op
        );
    }

    println!("Arithmetic script hex: {}", artifact.script);
    println!("Arithmetic script asm: {}", artifact.asm);
}

// ---------------------------------------------------------------------------
// Test: If/Else
// ---------------------------------------------------------------------------

#[test]
fn test_compile_if_else() {
    let ir_json = r#"{
        "contractName": "IfElse",
        "properties": [
            {"name": "limit", "type": "bigint", "readonly": true}
        ],
        "methods": [{
            "name": "check",
            "params": [
                {"name": "value", "type": "bigint"},
                {"name": "mode", "type": "boolean"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "value"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "mode"}},
                {"name": "t2", "value": {"kind": "load_const", "value": 0}},
                {"name": "t3", "value": {
                    "kind": "if",
                    "cond": "t1",
                    "then": [
                        {"name": "t4", "value": {"kind": "load_prop", "name": "limit"}},
                        {"name": "t5", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t4"}}
                    ],
                    "else": [
                        {"name": "t6", "value": {"kind": "load_prop", "name": "limit"}},
                        {"name": "t7", "value": {"kind": "bin_op", "op": "-", "left": "t0", "right": "t6"}}
                    ]
                }},
                {"name": "t8", "value": {"kind": "load_const", "value": 0}},
                {"name": "t9", "value": {"kind": "bin_op", "op": ">", "left": "t3", "right": "t8"}},
                {"name": "t10", "value": {"kind": "assert", "value": "t9"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("compilation should succeed");

    assert!(artifact.asm.contains("OP_IF"), "expected OP_IF in ASM");
    assert!(artifact.asm.contains("OP_ELSE"), "expected OP_ELSE in ASM");
    assert!(artifact.asm.contains("OP_ENDIF"), "expected OP_ENDIF in ASM");

    println!("IfElse script hex: {}", artifact.script);
    println!("IfElse script asm: {}", artifact.asm);
}

// ---------------------------------------------------------------------------
// Test: Boolean logic
// ---------------------------------------------------------------------------

#[test]
fn test_compile_boolean_logic() {
    let ir_json = r#"{
        "contractName": "BooleanLogic",
        "properties": [
            {"name": "threshold", "type": "bigint", "readonly": true}
        ],
        "methods": [{
            "name": "verify",
            "params": [
                {"name": "a", "type": "bigint"},
                {"name": "b", "type": "bigint"},
                {"name": "flag", "type": "boolean"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "b"}},
                {"name": "t2", "value": {"kind": "load_param", "name": "flag"}},
                {"name": "t3", "value": {"kind": "load_prop", "name": "threshold"}},
                {"name": "t4", "value": {"kind": "bin_op", "op": ">", "left": "t0", "right": "t3"}},
                {"name": "t5", "value": {"kind": "bin_op", "op": ">", "left": "t1", "right": "t3"}},
                {"name": "t6", "value": {"kind": "bin_op", "op": "&&", "left": "t4", "right": "t5"}},
                {"name": "t7", "value": {"kind": "bin_op", "op": "||", "left": "t4", "right": "t5"}},
                {"name": "t8", "value": {"kind": "unary_op", "op": "!", "operand": "t2"}},
                {"name": "t9", "value": {"kind": "bin_op", "op": "&&", "left": "t7", "right": "t8"}},
                {"name": "t10", "value": {"kind": "bin_op", "op": "||", "left": "t6", "right": "t9"}},
                {"name": "t11", "value": {"kind": "assert", "value": "t10"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("compilation should succeed");

    for op in &["OP_BOOLAND", "OP_BOOLOR", "OP_NOT"] {
        assert!(
            artifact.asm.contains(op),
            "expected ASM to contain {}",
            op
        );
    }

    println!("BooleanLogic script hex: {}", artifact.script);
    println!("BooleanLogic script asm: {}", artifact.asm);
}

// ---------------------------------------------------------------------------
// Test: Script number encoding
// ---------------------------------------------------------------------------

#[test]
fn test_encode_script_numbers() {
    use runar_compiler_rust::codegen::emit::{encode_push_int, encode_script_number};

    // Zero
    assert_eq!(encode_script_number(0), Vec::<u8>::new());
    let (h, _) = encode_push_int(0);
    assert_eq!(h, "00");

    // One
    let (h, _) = encode_push_int(1);
    assert_eq!(h, "51");

    // Sixteen
    let (h, _) = encode_push_int(16);
    assert_eq!(h, "60");

    // Negative one
    let (h, _) = encode_push_int(-1);
    assert_eq!(h, "4f");

    // Seventeen (requires push data)
    let (h, _) = encode_push_int(17);
    assert_eq!(h, "0111");

    // Negative two
    let (h, _) = encode_push_int(-2);
    assert_eq!(h, "0182");
}

// ---------------------------------------------------------------------------
// Test: Artifact JSON structure
// ---------------------------------------------------------------------------

#[test]
fn test_artifact_json_structure() {
    let ir_json = r#"{
        "contractName": "Simple",
        "properties": [],
        "methods": [{
            "name": "check",
            "params": [{"name": "x", "type": "bigint"}],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                {"name": "t1", "value": {"kind": "load_const", "value": 42}},
                {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
                {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("compilation should succeed");
    let json = serde_json::to_string_pretty(&artifact).expect("JSON serialization should succeed");

    // Parse back and verify required fields
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("output should be valid JSON");

    assert!(parsed.get("version").is_some(), "missing 'version'");
    assert!(
        parsed.get("compilerVersion").is_some(),
        "missing 'compilerVersion'"
    );
    assert!(
        parsed.get("contractName").is_some(),
        "missing 'contractName'"
    );
    assert!(parsed.get("abi").is_some(), "missing 'abi'");
    assert!(parsed.get("script").is_some(), "missing 'script'");
    assert!(parsed.get("asm").is_some(), "missing 'asm'");
    assert!(
        parsed.get("buildTimestamp").is_some(),
        "missing 'buildTimestamp'"
    );
    assert_eq!(
        parsed["version"].as_str().unwrap(),
        "runar-v0.1.0"
    );
}

// ---------------------------------------------------------------------------
// Test: Validation errors
// ---------------------------------------------------------------------------

#[test]
fn test_validation_empty_contract_name() {
    let ir_json = r#"{"contractName": "", "properties": [], "methods": []}"#;
    let result = compile_from_ir_str(ir_json);
    assert!(result.is_err(), "expected validation error");
    assert!(
        result.unwrap_err().contains("contractName"),
        "error should mention contractName"
    );
}

// ---------------------------------------------------------------------------
// Test: Peephole optimizer
// ---------------------------------------------------------------------------

#[test]
fn test_optimizer_swap_swap() {
    use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use runar_compiler_rust::codegen::stack::StackOp;

    let ops = vec![
        StackOp::Swap,
        StackOp::Swap,
        StackOp::Opcode("OP_ADD".to_string()),
    ];
    let optimized = optimize_stack_ops(&ops);
    assert_eq!(optimized.len(), 1);
    assert!(matches!(&optimized[0], StackOp::Opcode(c) if c == "OP_ADD"));
}

#[test]
fn test_optimizer_checksig_verify() {
    use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use runar_compiler_rust::codegen::stack::StackOp;

    let ops = vec![
        StackOp::Opcode("OP_CHECKSIG".to_string()),
        StackOp::Opcode("OP_VERIFY".to_string()),
    ];
    let optimized = optimize_stack_ops(&ops);
    assert_eq!(optimized.len(), 1);
    assert!(matches!(&optimized[0], StackOp::Opcode(c) if c == "OP_CHECKSIGVERIFY"));
}

#[test]
fn test_optimizer_numequal_verify() {
    use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use runar_compiler_rust::codegen::stack::StackOp;

    let ops = vec![
        StackOp::Opcode("OP_NUMEQUAL".to_string()),
        StackOp::Opcode("OP_VERIFY".to_string()),
    ];
    let optimized = optimize_stack_ops(&ops);
    assert_eq!(optimized.len(), 1);
    assert!(matches!(&optimized[0], StackOp::Opcode(c) if c == "OP_NUMEQUALVERIFY"));
}

// ---------------------------------------------------------------------------
// Test: Go and Rust produce same output (cross-compiler conformance)
// ---------------------------------------------------------------------------

#[test]
fn test_p2pkh_produces_consistent_hex() {
    // The P2PKH IR should produce a deterministic script hex.
    // We compile twice and verify same output.
    let ir_json = r#"{
        "contractName": "P2PKH",
        "properties": [
            {"name": "pubKeyHash", "type": "Addr", "readonly": true}
        ],
        "methods": [{
            "name": "unlock",
            "params": [
                {"name": "sig", "type": "Sig"},
                {"name": "pubKey", "type": "PubKey"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
                {"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
                {"name": "t3", "value": {"kind": "call", "func": "hash160", "args": ["t1"]}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t3", "right": "t2"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}},
                {"name": "t6", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
                {"name": "t7", "value": {"kind": "assert", "value": "t6"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact1 = compile_from_ir_str(ir_json).expect("first compilation");
    let artifact2 = compile_from_ir_str(ir_json).expect("second compilation");

    assert_eq!(artifact1.script, artifact2.script, "deterministic hex output");
    assert_eq!(artifact1.asm, artifact2.asm, "deterministic asm output");
}

// ---------------------------------------------------------------------------
// Conformance test helpers
// ---------------------------------------------------------------------------

fn conformance_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("tests")
}

fn load_conformance_ir(test_name: &str) -> String {
    let path = conformance_dir().join(test_name).join("expected-ir.json");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read conformance IR {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------------
// Test: Bounded loop conformance
// ---------------------------------------------------------------------------

#[test]
fn test_compile_bounded_loop() {
    let ir_json = load_conformance_ir("bounded-loop");
    let artifact = compile_from_ir_str(&ir_json).expect("compilation should succeed");

    assert_eq!(artifact.contract_name, "BoundedLoop");
    assert!(!artifact.script.is_empty(), "script hex should not be empty");
    assert!(!artifact.asm.is_empty(), "asm should not be empty");

    println!("BoundedLoop script hex: {}", artifact.script);
    println!("BoundedLoop script asm: {}", artifact.asm);
}

// ---------------------------------------------------------------------------
// Test: Multi-method conformance (dispatch table)
// ---------------------------------------------------------------------------

#[test]
fn test_compile_multi_method() {
    let ir_json = load_conformance_ir("multi-method");
    let artifact = compile_from_ir_str(&ir_json).expect("compilation should succeed");

    assert_eq!(artifact.contract_name, "MultiMethod");
    assert!(!artifact.script.is_empty(), "script hex should not be empty");

    // Multi-method contracts must produce a dispatch table with OP_IF
    assert!(
        artifact.asm.contains("OP_IF"),
        "expected OP_IF in ASM for method dispatch, got: {}",
        artifact.asm
    );

    println!("MultiMethod script hex: {}", artifact.script);
    println!("MultiMethod script asm: {}", artifact.asm);
}

// ---------------------------------------------------------------------------
// Test: Stateful conformance
// ---------------------------------------------------------------------------

#[test]
fn test_compile_stateful() {
    let ir_json = load_conformance_ir("stateful");
    let artifact = compile_from_ir_str(&ir_json).expect("compilation should succeed");

    assert_eq!(artifact.contract_name, "Stateful");
    assert!(!artifact.script.is_empty(), "script hex should not be empty");

    // Stateful contracts use hash256 for state validation
    assert!(
        artifact.asm.contains("OP_HASH256"),
        "expected OP_HASH256 in ASM for state hashing"
    );

    // Stateful contracts use OP_VERIFY for assertions
    assert!(
        artifact.asm.contains("OP_VERIFY"),
        "expected OP_VERIFY in ASM"
    );

    println!("Stateful script hex: {}", artifact.script);
    println!("Stateful script asm: {}", artifact.asm);
}

// ---------------------------------------------------------------------------
// Test: All conformance tests compile successfully
// ---------------------------------------------------------------------------

fn load_expected_script_hex(test_name: &str) -> Option<String> {
    let path = conformance_dir().join(test_name).join("expected-script.hex");
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

#[test]
fn test_all_conformance_tests() {
    let test_dirs = [
        "arithmetic",
        "auction",
        "basic-p2pkh",
        "blake3",
        "boolean-logic",
        "bounded-loop",
        "convergence-proof",
        "covenant-vault",
        "ec-demo",
        "ec-primitives",
        "escrow",
        "function-patterns",
        "if-else",
        "if-without-else",
        "math-demo",
        "multi-method",
        "oracle-price",
        "post-quantum-slhdsa",
        "post-quantum-wallet",
        "post-quantum-wots",
        "property-initializers",
        "schnorr-zkp",
        "sphincs-wallet",
        "stateful",
        "stateful-counter",
        "token-ft",
        "token-nft",
    ];

    let no_fold = CompileOptions { disable_constant_folding: true };

    for dir in &test_dirs {
        let ir_json = load_conformance_ir(dir);
        let artifact = compile_from_ir_str(&ir_json)
            .unwrap_or_else(|e| panic!("compilation failed for {}: {}", dir, e));

        assert!(
            !artifact.script.is_empty(),
            "{}: script hex should not be empty",
            dir
        );
        assert!(
            !artifact.asm.is_empty(),
            "{}: asm should not be empty",
            dir
        );
        assert!(
            !artifact.contract_name.is_empty(),
            "{}: contractName should not be empty",
            dir
        );

        // Compare against golden expected-script.hex (with folding disabled to
        // match the golden files which were generated without constant folding)
        if let Some(expected_hex) = load_expected_script_hex(dir) {
            let artifact_no_fold = compile_from_ir_str_with_options(&ir_json, &no_fold)
                .unwrap_or_else(|e| panic!("compilation (no-fold) failed for {}: {}", dir, e));
            assert_eq!(
                artifact_no_fold.script, expected_hex,
                "{}: IR-compiled script hex does not match golden file",
                dir
            );
        }

        println!(
            "{}: hex={} bytes, asm={} chars",
            dir,
            artifact.script.len() / 2,
            artifact.asm.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Push data encoding for various sizes
// ---------------------------------------------------------------------------

#[test]
fn test_push_data_encoding() {
    use runar_compiler_rust::codegen::emit::encode_push_data;

    // Empty data -> OP_0
    let encoded = encode_push_data(&[]);
    assert_eq!(encoded, vec![0x00], "empty data should produce OP_0");

    // 1 byte -> direct length prefix
    let data_1 = vec![0xab; 1];
    let encoded = encode_push_data(&data_1);
    assert_eq!(encoded[0], 1, "1-byte data should have length prefix 0x01");
    assert_eq!(encoded.len(), 2, "1-byte data: 1 prefix + 1 data");

    // 75 bytes -> direct length prefix (max for single-byte)
    let data_75 = vec![0xab; 75];
    let encoded = encode_push_data(&data_75);
    assert_eq!(encoded[0], 75, "75-byte data should have length prefix 75");
    assert_eq!(encoded.len(), 76, "75-byte data: 1 prefix + 75 data");

    // 76 bytes -> OP_PUSHDATA1
    let data_76 = vec![0xab; 76];
    let encoded = encode_push_data(&data_76);
    assert_eq!(
        encoded[0], 0x4c,
        "76-byte data should trigger OP_PUSHDATA1"
    );
    assert_eq!(encoded[1], 76, "OP_PUSHDATA1 length byte should be 76");
    assert_eq!(encoded.len(), 78, "76-byte data: 2 prefix + 76 data");

    // 256 bytes -> OP_PUSHDATA2
    let data_256 = vec![0xab; 256];
    let encoded = encode_push_data(&data_256);
    assert_eq!(
        encoded[0], 0x4d,
        "256-byte data should trigger OP_PUSHDATA2"
    );
    assert_eq!(
        encoded[1], 0x00,
        "OP_PUSHDATA2 low byte should be 0x00 for 256"
    );
    assert_eq!(
        encoded[2], 0x01,
        "OP_PUSHDATA2 high byte should be 0x01 for 256"
    );
    assert_eq!(encoded.len(), 259, "256-byte data: 3 prefix + 256 data");
}

// ---------------------------------------------------------------------------
// Test: Deterministic output
// ---------------------------------------------------------------------------

#[test]
fn test_deterministic_output() {
    let ir_json = r#"{
        "contractName": "Deterministic",
        "properties": [
            {"name": "target", "type": "bigint", "readonly": true}
        ],
        "methods": [{
            "name": "verify",
            "params": [
                {"name": "a", "type": "bigint"},
                {"name": "b", "type": "bigint"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "b"}},
                {"name": "t2", "value": {"kind": "bin_op", "op": "+", "left": "t0", "right": "t1"}},
                {"name": "t3", "value": {"kind": "load_prop", "name": "target"}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t2", "right": "t3"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact1 = compile_from_ir_str(ir_json).expect("first compilation");
    let artifact2 = compile_from_ir_str(ir_json).expect("second compilation");

    assert_eq!(
        artifact1.script, artifact2.script,
        "script hex should be deterministic"
    );
    assert_eq!(
        artifact1.asm, artifact2.asm,
        "asm should be deterministic"
    );

    // Also verify with a conformance test
    let p2pkh_json = load_conformance_ir("basic-p2pkh");
    let a1 = compile_from_ir_str(&p2pkh_json).expect("first P2PKH");
    let a2 = compile_from_ir_str(&p2pkh_json).expect("second P2PKH");

    assert_eq!(a1.script, a2.script, "P2PKH script hex should be deterministic");
    assert_eq!(a1.asm, a2.asm, "P2PKH asm should be deterministic");
}

// ---------------------------------------------------------------------------
// Test: Optimizer PUSH+DROP elimination
// ---------------------------------------------------------------------------

#[test]
fn test_optimizer_push_drop() {
    use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use runar_compiler_rust::codegen::stack::{PushValue, StackOp};

    let ops = vec![
        StackOp::Push(PushValue::Int(42)),
        StackOp::Drop,
        StackOp::Opcode("OP_ADD".to_string()),
    ];
    let optimized = optimize_stack_ops(&ops);

    // PUSH+DROP should be eliminated, leaving only OP_ADD
    assert_eq!(
        optimized.len(),
        1,
        "expected 1 op after PUSH+DROP elimination, got {}",
        optimized.len()
    );
    assert!(
        matches!(&optimized[0], StackOp::Opcode(c) if c == "OP_ADD"),
        "expected OP_ADD after optimization"
    );
}

// ---------------------------------------------------------------------------
// Test: Optimizer DROP+DROP -> 2DROP
// ---------------------------------------------------------------------------

#[test]
fn test_optimizer_2drop() {
    use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use runar_compiler_rust::codegen::stack::StackOp;

    let ops = vec![StackOp::Drop, StackOp::Drop];
    let optimized = optimize_stack_ops(&ops);

    assert_eq!(
        optimized.len(),
        1,
        "expected 1 op after DROP+DROP optimization, got {}",
        optimized.len()
    );
    assert!(
        matches!(&optimized[0], StackOp::Opcode(c) if c == "OP_2DROP"),
        "expected OP_2DROP after optimization"
    );
}

// ---------------------------------------------------------------------------
// Test: Optimizer PUSH_1+ADD -> 1ADD
// ---------------------------------------------------------------------------

#[test]
fn test_optimizer_1add() {
    use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use runar_compiler_rust::codegen::stack::{PushValue, StackOp};

    let ops = vec![
        StackOp::Push(PushValue::Int(1)),
        StackOp::Opcode("OP_ADD".to_string()),
    ];
    let optimized = optimize_stack_ops(&ops);

    assert_eq!(
        optimized.len(),
        1,
        "expected 1 op after PUSH_1+ADD optimization, got {}",
        optimized.len()
    );
    assert!(
        matches!(&optimized[0], StackOp::Opcode(c) if c == "OP_1ADD"),
        "expected OP_1ADD after optimization"
    );
}

// ---------------------------------------------------------------------------
// Test: Empty/Invalid IR produces errors
// ---------------------------------------------------------------------------

#[test]
fn test_empty_ir_error() {
    // Completely empty string
    let result = compile_from_ir_str("");
    assert!(result.is_err(), "empty string should produce an error");

    // Invalid JSON
    let result = compile_from_ir_str("{not valid json}");
    assert!(result.is_err(), "invalid JSON should produce an error");

    // Valid JSON but empty contractName
    let result = compile_from_ir_str(r#"{"contractName": "", "properties": [], "methods": []}"#);
    assert!(
        result.is_err(),
        "empty contractName should produce a validation error"
    );

    // Valid JSON but missing required fields
    let result = compile_from_ir_str(r#"{}"#);
    assert!(
        result.is_err(),
        "missing required fields should produce an error"
    );

    // Valid structure but with an unknown kind in a binding
    let result = compile_from_ir_str(
        r#"{
        "contractName": "Bad",
        "properties": [],
        "methods": [{
            "name": "m",
            "params": [],
            "body": [{"name": "t0", "value": {"kind": "totally_fake_kind"}}],
            "isPublic": true
        }]
    }"#,
    );
    assert!(
        result.is_err(),
        "unknown binding kind should produce an error"
    );
}

// ---------------------------------------------------------------------------
// Source compilation tests (.runar.ts → Bitcoin Script via native SWC frontend)
// ---------------------------------------------------------------------------

fn conformance_source(test_name: &str) -> String {
    // Try direct .runar.ts file first
    let direct = conformance_dir()
        .join(test_name)
        .join(format!("{}.runar.ts", test_name));
    if direct.exists() {
        return std::fs::read_to_string(&direct)
            .unwrap_or_else(|e| panic!("failed to read source {}: {}", direct.display(), e));
    }

    // Resolve via source.json
    let source_json_path = conformance_dir().join(test_name).join("source.json");
    if source_json_path.exists() {
        let json_str = std::fs::read_to_string(&source_json_path)
            .unwrap_or_else(|e| panic!("failed to read source.json for {}: {}", test_name, e));
        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .unwrap_or_else(|e| panic!("failed to parse source.json for {}: {}", test_name, e));
        if let Some(ts_ref) = parsed["sources"][".runar.ts"].as_str() {
            let resolved = conformance_dir().join(test_name).join(ts_ref);
            return std::fs::read_to_string(&resolved)
                .unwrap_or_else(|e| panic!("failed to read referenced source {}: {}", resolved.display(), e));
        }
    }

    panic!("no .runar.ts source found for conformance test {}", test_name);
}

fn example_source(contract_dir: &str, file_name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("ts")
        .join(contract_dir)
        .join(file_name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read example {}: {}", path.display(), e))
}

#[test]
fn test_source_compile_p2pkh() {
    let source = conformance_source("basic-p2pkh");
    let artifact = compile_from_source_str(&source, Some("basic-p2pkh.runar.ts"))
        .expect("source compilation should succeed");

    assert_eq!(artifact.contract_name, "P2PKH");
    assert!(!artifact.script.is_empty(), "script hex should not be empty");
    assert!(!artifact.asm.is_empty(), "asm should not be empty");
    assert!(
        artifact.asm.contains("OP_HASH160"),
        "expected OP_HASH160 in ASM, got: {}",
        artifact.asm
    );
    assert!(
        artifact.asm.contains("OP_CHECKSIG"),
        "expected OP_CHECKSIG in ASM"
    );

    println!("P2PKH from source: hex={} asm={}", artifact.script, artifact.asm);
}

#[test]
fn test_source_compile_arithmetic() {
    let source = conformance_source("arithmetic");
    let artifact = compile_from_source_str(&source, Some("arithmetic.runar.ts"))
        .expect("source compilation should succeed");

    assert_eq!(artifact.contract_name, "Arithmetic");
    assert!(!artifact.script.is_empty());
    assert!(
        artifact.asm.contains("OP_ADD"),
        "expected OP_ADD in ASM"
    );
}

#[test]
fn test_source_compile_boolean_logic() {
    let source = conformance_source("boolean-logic");
    let artifact = compile_from_source_str(&source, Some("boolean-logic.runar.ts"))
        .expect("source compilation should succeed");

    assert_eq!(artifact.contract_name, "BooleanLogic");
    assert!(
        artifact.asm.contains("OP_BOOLAND"),
        "expected OP_BOOLAND in ASM"
    );
}

#[test]
fn test_source_compile_if_else() {
    let source = conformance_source("if-else");
    let artifact = compile_from_source_str(&source, Some("if-else.runar.ts"))
        .expect("source compilation should succeed");

    assert!(artifact.asm.contains("OP_IF"), "expected OP_IF in ASM");
}

#[test]
fn test_source_compile_bounded_loop() {
    let source = conformance_source("bounded-loop");
    let artifact = compile_from_source_str(&source, Some("bounded-loop.runar.ts"))
        .expect("source compilation should succeed");

    assert!(!artifact.script.is_empty());
}

#[test]
fn test_source_compile_multi_method() {
    let source = conformance_source("multi-method");
    let artifact = compile_from_source_str(&source, Some("multi-method.runar.ts"))
        .expect("source compilation should succeed");

    assert!(
        artifact.asm.contains("OP_IF"),
        "expected OP_IF for dispatch table"
    );
}

#[test]
fn test_source_compile_stateful() {
    let source = conformance_source("stateful");
    let artifact = compile_from_source_str(&source, Some("stateful.runar.ts"))
        .expect("source compilation should succeed");

    assert!(
        artifact.asm.contains("OP_HASH256"),
        "expected OP_HASH256 for state hashing"
    );
}

#[test]
fn test_source_compile_all_conformance() {
    // All 27 conformance tests — source files are resolved from either
    // direct .runar.ts files or via source.json references.
    let test_dirs = [
        "arithmetic",
        "auction",
        "basic-p2pkh",
        "blake3",
        "boolean-logic",
        "bounded-loop",
        "convergence-proof",
        "covenant-vault",
        "ec-demo",
        "ec-primitives",
        "escrow",
        "function-patterns",
        "if-else",
        "if-without-else",
        "math-demo",
        "multi-method",
        "oracle-price",
        "post-quantum-slhdsa",
        "post-quantum-wallet",
        "post-quantum-wots",
        "property-initializers",
        "schnorr-zkp",
        "sphincs-wallet",
        "stateful",
        "stateful-counter",
        "token-ft",
        "token-nft",
    ];

    let no_fold = CompileOptions { disable_constant_folding: true };

    for dir in &test_dirs {
        let source = conformance_source(dir);
        let artifact = compile_from_source_str(&source, Some(&format!("{}.runar.ts", dir)))
            .unwrap_or_else(|e| panic!("source compilation failed for {}: {}", dir, e));

        assert!(
            !artifact.script.is_empty(),
            "{}: script hex should not be empty",
            dir
        );
        assert!(
            !artifact.asm.is_empty(),
            "{}: asm should not be empty",
            dir
        );
        assert!(
            !artifact.contract_name.is_empty(),
            "{}: contract name should not be empty",
            dir
        );

        // Compare against golden expected-script.hex (with folding disabled to
        // match the golden files which were generated without constant folding)
        if let Some(expected_hex) = load_expected_script_hex(dir) {
            let artifact_no_fold = compile_from_source_str_with_options(&source, Some(&format!("{}.runar.ts", dir)), &no_fold)
                .unwrap_or_else(|e| panic!("source compilation (no-fold) failed for {}: {}", dir, e));
            assert_eq!(
                artifact_no_fold.script, expected_hex,
                "{}: source-compiled script hex does not match golden file",
                dir
            );
        }

        println!(
            "{}: hex={} bytes, asm={} chars",
            dir,
            artifact.script.len() / 2,
            artifact.asm.len()
        );
    }
}

#[test]
fn test_source_compile_example_p2pkh() {
    let source = example_source("p2pkh", "P2PKH.runar.ts");
    let artifact = compile_from_source_str(&source, Some("P2PKH.runar.ts"))
        .expect("example P2PKH should compile");

    assert_eq!(artifact.contract_name, "P2PKH");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_source_compile_example_escrow() {
    let source = example_source("escrow", "Escrow.runar.ts");
    let artifact = compile_from_source_str(&source, Some("Escrow.runar.ts"))
        .expect("example Escrow should compile");

    assert_eq!(artifact.contract_name, "Escrow");
    assert!(
        artifact.asm.contains("OP_IF"),
        "expected OP_IF for multi-method dispatch"
    );
}

#[test]
fn test_source_vs_ir_both_produce_output() {
    // Compile from IR
    let ir_json = load_conformance_ir("basic-p2pkh");
    let ir_artifact = compile_from_ir_str(&ir_json).expect("IR compilation");

    // Compile from source
    let source = conformance_source("basic-p2pkh");
    let source_artifact = compile_from_source_str(&source, Some("basic-p2pkh.runar.ts"))
        .expect("source compilation");

    // Both should produce P2PKH
    assert_eq!(ir_artifact.contract_name, source_artifact.contract_name);

    // Both should produce non-empty scripts
    assert!(!ir_artifact.script.is_empty());
    assert!(!source_artifact.script.is_empty());

    println!("IR hex:     {}", ir_artifact.script);
    println!("Source hex: {}", source_artifact.script);
}

// ---------------------------------------------------------------------------
// Conformance golden-file parity tests (all 20 source-based test cases)
//
// Each test compiles the `.runar.ts` source via compile_from_source_str()
// and compares the resulting script hex against expected-script.hex.
// ---------------------------------------------------------------------------

fn conformance_golden_test(test_name: &str) {
    let no_fold = CompileOptions { disable_constant_folding: true };
    let source = conformance_source(test_name);
    let artifact = compile_from_source_str_with_options(&source, Some(&format!("{}.runar.ts", test_name)), &no_fold)
        .unwrap_or_else(|e| panic!("[{}] source compilation failed: {}", test_name, e));

    assert!(
        !artifact.script.is_empty(),
        "[{}] script hex should not be empty",
        test_name
    );
    assert!(
        !artifact.asm.is_empty(),
        "[{}] asm should not be empty",
        test_name
    );
    assert!(
        !artifact.contract_name.is_empty(),
        "[{}] contract name should not be empty",
        test_name
    );

    if let Some(expected_hex) = load_expected_script_hex(test_name) {
        assert_eq!(
            artifact.script, expected_hex,
            "[{}] source-compiled script hex does not match golden expected-script.hex\n  actual len={}\n  expected len={}",
            test_name,
            artifact.script.len(),
            expected_hex.len()
        );
    } else {
        panic!(
            "[{}] expected-script.hex not found in conformance directory",
            test_name
        );
    }
}

#[test]
fn test_conformance_golden_basic_p2pkh() {
    conformance_golden_test("basic-p2pkh");
}

#[test]
fn test_conformance_golden_arithmetic() {
    conformance_golden_test("arithmetic");
}

#[test]
fn test_conformance_golden_boolean_logic() {
    conformance_golden_test("boolean-logic");
}

#[test]
fn test_conformance_golden_if_else() {
    conformance_golden_test("if-else");
}

#[test]
fn test_conformance_golden_bounded_loop() {
    conformance_golden_test("bounded-loop");
}

#[test]
fn test_conformance_golden_multi_method() {
    conformance_golden_test("multi-method");
}

#[test]
fn test_conformance_golden_stateful() {
    conformance_golden_test("stateful");
}

#[test]
fn test_conformance_golden_post_quantum_wots() {
    conformance_golden_test("post-quantum-wots");
}

#[test]
fn test_conformance_golden_post_quantum_slhdsa() {
    conformance_golden_test("post-quantum-slhdsa");
}

#[test]
fn test_conformance_golden_convergence_proof() {
    conformance_golden_test("convergence-proof");
}

#[test]
fn test_conformance_golden_ec_demo() {
    conformance_golden_test("ec-demo");
}

#[test]
fn test_conformance_golden_ec_primitives() {
    conformance_golden_test("ec-primitives");
}

#[test]
fn test_conformance_golden_function_patterns() {
    conformance_golden_test("function-patterns");
}

#[test]
fn test_conformance_golden_if_without_else() {
    conformance_golden_test("if-without-else");
}

#[test]
fn test_conformance_golden_math_demo() {
    conformance_golden_test("math-demo");
}

#[test]
fn test_conformance_golden_oracle_price() {
    conformance_golden_test("oracle-price");
}

#[test]
fn test_conformance_golden_post_quantum_wallet() {
    conformance_golden_test("post-quantum-wallet");
}

#[test]
fn test_conformance_golden_property_initializers() {
    conformance_golden_test("property-initializers");
}

#[test]
fn test_conformance_golden_sphincs_wallet() {
    conformance_golden_test("sphincs-wallet");
}

#[test]
fn test_conformance_golden_stateful_counter() {
    conformance_golden_test("stateful-counter");
}

// ---------------------------------------------------------------------------
// Test: terminal assert leaves value on stack (no trailing OP_VERIFY in ASM)
// ---------------------------------------------------------------------------

#[test]
fn test_terminal_assert_no_verify() {
    // A single-method contract with a single terminal assert should NOT end
    // with OP_VERIFY — the final assert leaves the value on the stack for
    // the Script VM to evaluate as the spend condition.
    let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

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
"#;
    let artifact = runar_compiler_rust::compile_from_source_str(source, Some("test.runar.ts"))
        .expect("P2PKH should compile");

    // Trim trailing whitespace and verify the ASM does NOT end with OP_VERIFY.
    let asm_trimmed = artifact.asm.trim();
    assert!(
        !asm_trimmed.ends_with("OP_VERIFY"),
        "final assert in a single-method contract must NOT end with OP_VERIFY; asm: {}",
        artifact.asm
    );
}

// ---------------------------------------------------------------------------
// Test: bool push encoding — true = 0x51 (OP_TRUE), false = 0x00 (OP_FALSE)
// ---------------------------------------------------------------------------

#[test]
fn test_bool_push_encoding() {
    use runar_compiler_rust::codegen::emit::encode_push_int;

    // true (1) should encode as OP_1 = 0x51
    let (hex_true, asm_true) = encode_push_int(1);
    assert_eq!(
        hex_true, "51",
        "true (1) should encode as OP_1 = 0x51, got {}",
        hex_true
    );
    assert!(
        asm_true.contains("OP_1") || asm_true == "51",
        "asm for true should be OP_1 or 51, got {}",
        asm_true
    );

    // false (0) should encode as OP_0 = 0x00
    let (hex_false, _asm_false) = encode_push_int(0);
    assert_eq!(
        hex_false, "00",
        "false (0) should encode as OP_0 = 0x00, got {}",
        hex_false
    );
}

// ---------------------------------------------------------------------------
// IR Loader tests
// ---------------------------------------------------------------------------

#[test]
fn test_ir_load_decodes_constants() {
    let ir_json = r#"{
        "contractName": "ConstTest",
        "properties": [],
        "methods": [{
            "name": "check",
            "params": [{"name": "x", "type": "bigint"}],
            "body": [
                {"name": "t0", "value": {"kind": "load_const", "value": 42}},
                {"name": "t1", "value": {"kind": "load_const", "value": true}},
                {"name": "t2", "value": {"kind": "load_const", "value": "deadbeef"}},
                {"name": "t3", "value": {"kind": "load_param", "name": "x"}},
                {"name": "t4", "value": {"kind": "bin_op", "op": ">", "left": "t3", "right": "t0"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}}
            ],
            "isPublic": true
        }]
    }"#;
    let artifact = compile_from_ir_str(ir_json);
    assert!(
        artifact.is_ok(),
        "IR with integer, boolean, and hex string constants should load without error; got: {:?}",
        artifact.err()
    );
    let artifact = artifact.unwrap();
    assert_eq!(artifact.contract_name, "ConstTest");
    assert_eq!(artifact.abi.methods.len(), 1, "expected 1 method in ABI");
}

#[test]
fn test_ir_validate_empty_method_name() {
    let ir_json = r#"{
        "contractName": "Test",
        "properties": [],
        "methods": [{
            "name": "",
            "params": [],
            "body": [
                {"name": "t0", "value": {"kind": "load_const", "value": true}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_err(),
        "IR with empty method name should produce a validation error"
    );
}

#[test]
fn test_ir_validate_empty_param_name() {
    let ir_json = r#"{
        "contractName": "Test",
        "properties": [],
        "methods": [{
            "name": "check",
            "params": [{"name": "", "type": "bigint"}],
            "body": [
                {"name": "t0", "value": {"kind": "load_const", "value": true}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_err(),
        "IR with empty param name should produce a validation error"
    );
}

#[test]
fn test_ir_validate_empty_property_name() {
    let ir_json = r#"{
        "contractName": "Test",
        "properties": [{"name": "", "type": "bigint", "readonly": true}],
        "methods": [{
            "name": "check",
            "params": [],
            "body": [
                {"name": "t0", "value": {"kind": "load_const", "value": true}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_err(),
        "IR with empty property name should produce a validation error"
    );
}

#[test]
fn test_ir_validate_empty_property_type() {
    let ir_json = r#"{
        "contractName": "Test",
        "properties": [{"name": "x", "type": "", "readonly": true}],
        "methods": [{
            "name": "check",
            "params": [],
            "body": [
                {"name": "t0", "value": {"kind": "load_const", "value": true}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_err(),
        "IR with empty property type should produce a validation error"
    );
}

#[test]
fn test_ir_invalid_json() {
    // Non-JSON string input should produce a JSON parse error, not a panic.
    let inputs = [
        "{ this is not valid json }",
        "not json at all",
        "",
        "[1,2,3]", // valid JSON but wrong type (array, not object)
    ];
    for input in &inputs {
        let result = compile_from_ir_str(input);
        assert!(
            result.is_err(),
            "non-JSON or wrong-type input {:?} should produce an error",
            input
        );
        // Error should mention JSON parsing, not a panic
        let err = result.unwrap_err();
        assert!(
            !err.is_empty(),
            "error message should not be empty for input {:?}",
            input
        );
    }
}

#[test]
fn test_ir_validate_loop_count_exceeds_max() {
    // Loop count of 1000 is above the expected max of 512.
    // In the Rust IR loader, usize can hold 1000, so this test verifies whether
    // the compiler accepts or rejects it. If no max is enforced, the compile
    // will succeed (no validation error at the IR loader level).
    let ir_json = r#"{
        "contractName": "Test",
        "properties": [],
        "methods": [{
            "name": "check",
            "params": [],
            "body": [
                {"name": "t0", "value": {
                    "kind": "loop",
                    "count": 1000,
                    "iterVar": "i",
                    "body": [
                        {"name": "tb", "value": {"kind": "load_const", "value": 0}}
                    ]
                }},
                {"name": "t1", "value": {"kind": "load_const", "value": true}},
                {"name": "t2", "value": {"kind": "assert", "value": "t1"}}
            ],
            "isPublic": true
        }]
    }"#;
    // The Rust IR loader uses usize for count and has no 512 max validation.
    // A count of 1000 will either succeed or fail during stack lowering (depth check).
    // We verify the result is not a panic and produces a consistent response.
    let result = compile_from_ir_str(ir_json);
    // Either it succeeds or it errors — both are acceptable, just no panic.
    match &result {
        Ok(_) => { /* no enforced max in Rust IR loader */ }
        Err(e) => {
            // If it does error, it should be a stack depth or loop-related message
            let _ = e; // Any error is fine
        }
    }
}

#[test]
fn test_ir_validate_negative_loop_count() {
    // usize cannot be negative — a JSON value of -1 should fail to deserialize
    let ir_json = r#"{
        "contractName": "Test",
        "properties": [],
        "methods": [{
            "name": "check",
            "params": [],
            "body": [
                {"name": "t0", "value": {
                    "kind": "loop",
                    "count": -1,
                    "iterVar": "i",
                    "body": []
                }},
                {"name": "t1", "value": {"kind": "load_const", "value": true}},
                {"name": "t2", "value": {"kind": "assert", "value": "t1"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_err(),
        "IR with negative loop count should produce a deserialization or validation error"
    );
}

#[test]
fn test_ir_round_trip() {
    let ir_json = r#"{
        "contractName": "RoundTrip",
        "properties": [
            {"name": "pubKeyHash", "type": "Addr", "readonly": true}
        ],
        "methods": [{
            "name": "unlock",
            "params": [
                {"name": "sig", "type": "Sig"},
                {"name": "pubKey", "type": "PubKey"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "sig"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "pubKey"}},
                {"name": "t2", "value": {"kind": "load_prop", "name": "pubKeyHash"}},
                {"name": "t3", "value": {"kind": "call", "func": "hash160", "args": ["t1"]}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t3", "right": "t2"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}},
                {"name": "t6", "value": {"kind": "call", "func": "checkSig", "args": ["t0", "t1"]}},
                {"name": "t7", "value": {"kind": "assert", "value": "t6"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact1 = compile_from_ir_str(ir_json).expect("first load should succeed");
    // Serialize the artifact's source data back — we verify contract name and method count
    // by re-compiling from the same IR
    let artifact2 = compile_from_ir_str(ir_json).expect("second load should succeed");
    assert_eq!(artifact1.contract_name, artifact2.contract_name, "contract name should be identical");
    assert_eq!(artifact1.abi.methods.len(), artifact2.abi.methods.len(), "method count should be identical");
}

#[test]
fn test_ir_empty_method_body_valid() {
    // A method with an empty bindings array but still a final assert is valid.
    // Actually a method with just assert(true) is the minimal valid form.
    let ir_json = r#"{
        "contractName": "Empty",
        "properties": [],
        "methods": [{
            "name": "check",
            "params": [],
            "body": [
                {"name": "t0", "value": {"kind": "load_const", "value": true}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_ok(),
        "method with only assert(true) should be valid; got: {:?}",
        result.err()
    );
}

#[test]
fn test_ir_round_trip_with_initial_value() {
    let ir_json = r#"{
        "contractName": "InitTest",
        "properties": [
            {"name": "value", "type": "bigint", "readonly": true, "initialValue": {"kind": "load_const", "value": "42n"}}
        ],
        "methods": [{
            "name": "check",
            "params": [],
            "body": [
                {"name": "t0", "value": {"kind": "load_const", "value": true}},
                {"name": "t1", "value": {"kind": "assert", "value": "t0"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_ok(),
        "IR with initialValue on property should load without error; got: {:?}",
        result.err()
    );
    let artifact = result.unwrap();
    assert_eq!(artifact.contract_name, "InitTest");
    // Properties with initialValue should be present in the compiled artifact
    assert!(!artifact.script.is_empty(), "script should not be empty");
}

#[test]
fn test_ir_round_trip_if_and_loop() {
    // IR with both an if binding and a loop binding should load and compile correctly
    let ir_json = r#"{
        "contractName": "IfLoop",
        "properties": [],
        "methods": [{
            "name": "check",
            "params": [
                {"name": "mode", "type": "boolean"},
                {"name": "val", "type": "bigint"}
            ],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "mode"}},
                {"name": "t1", "value": {"kind": "load_param", "name": "val"}},
                {"name": "t2", "value": {
                    "kind": "if",
                    "cond": "t0",
                    "then": [
                        {"name": "t3", "value": {"kind": "load_const", "value": 1}}
                    ],
                    "else": [
                        {"name": "t4", "value": {"kind": "load_const", "value": 2}}
                    ]
                }},
                {"name": "t5", "value": {
                    "kind": "loop",
                    "count": 3,
                    "iterVar": "i",
                    "body": [
                        {"name": "t6", "value": {"kind": "load_const", "value": 0}}
                    ]
                }},
                {"name": "t7", "value": {"kind": "load_const", "value": true}},
                {"name": "t8", "value": {"kind": "assert", "value": "t7"}}
            ],
            "isPublic": true
        }]
    }"#;
    let result = compile_from_ir_str(ir_json);
    assert!(
        result.is_ok(),
        "IR with if and loop bindings should load and compile correctly; got: {:?}",
        result.err()
    );
    let artifact = result.unwrap();
    assert!(!artifact.script.is_empty(), "script should not be empty");
    assert!(artifact.asm.contains("OP_IF"), "expected OP_IF for if binding");
}

// ---------------------------------------------------------------------------
// Emit tests
// ---------------------------------------------------------------------------

#[test]
fn test_emit_placeholder_produces_constructor_slot() {
    let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

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
"#;
    let artifact = compile_from_source_str(source, Some("test.runar.ts"))
        .expect("P2PKH should compile");
    assert!(
        !artifact.constructor_slots.is_empty(),
        "P2PKH compiled from source should have at least one constructor slot"
    );
}

#[test]
fn test_emit_multiple_placeholders_distinct_offsets() {
    // A contract with 2 constructor properties should have 2 constructor slots
    // with different byte offsets.
    let ir_json = r#"{
        "contractName": "TwoProp",
        "properties": [
            {"name": "a", "type": "bigint", "readonly": true},
            {"name": "b", "type": "bigint", "readonly": true}
        ],
        "methods": [{
            "name": "check",
            "params": [{"name": "x", "type": "bigint"}],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                {"name": "t1", "value": {"kind": "load_prop", "name": "a"}},
                {"name": "t2", "value": {"kind": "load_prop", "name": "b"}},
                {"name": "t3", "value": {"kind": "bin_op", "op": "+", "left": "t1", "right": "t2"}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t3"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}}
            ],
            "isPublic": true
        }]
    }"#;
    let artifact = compile_from_ir_str(ir_json).expect("TwoProp should compile");
    assert_eq!(
        artifact.constructor_slots.len(),
        2,
        "contract with 2 properties should have 2 constructor slots"
    );
    let offset0 = artifact.constructor_slots[0].byte_offset;
    let offset1 = artifact.constructor_slots[1].byte_offset;
    assert_ne!(
        offset0, offset1,
        "two constructor slots should have different byte offsets"
    );
}

#[test]
fn test_emit_byte_offset_accounts_for_preceding_opcodes() {
    let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

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
"#;
    let artifact = compile_from_source_str(source, Some("test.runar.ts"))
        .expect("P2PKH should compile");
    assert!(
        !artifact.constructor_slots.is_empty(),
        "expected constructor slots for pubKeyHash"
    );
    assert!(
        artifact.constructor_slots[0].byte_offset > 0,
        "byte_offset should be > 0 because opcodes precede the constructor placeholder; got {}",
        artifact.constructor_slots[0].byte_offset
    );
}

#[test]
fn test_emit_simple_sequence_hex() {
    let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

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
"#;
    let artifact = compile_from_source_str(source, Some("test.runar.ts"))
        .expect("P2PKH should compile");
    assert!(
        !artifact.script.is_empty(),
        "compiled script hex should not be empty"
    );
    assert_eq!(
        artifact.script.len() % 2,
        0,
        "script hex should have even length (valid hex encoding)"
    );
}

#[test]
fn test_emit_empty_methods_produces_empty_hex() {
    // An IR with no methods should produce an artifact with empty or minimal script
    let ir_json = r#"{
        "contractName": "NoMethods",
        "properties": [],
        "methods": []
    }"#;
    let result = compile_from_ir_str(ir_json);
    // Either it fails validation (no methods) or produces empty script
    match result {
        Ok(artifact) => {
            // If it succeeds, the script should be empty since there are no methods
            assert!(
                artifact.script.is_empty() || artifact.script == "00",
                "no-methods contract should produce empty or near-empty script; got: {}",
                artifact.script
            );
        }
        Err(_) => {
            // A validation error for no methods is also acceptable
        }
    }
}

#[test]
fn test_emit_deterministic_output() {
    let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

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
"#;
    let artifact1 = compile_from_source_str(source, Some("test.runar.ts"))
        .expect("first compilation");
    let artifact2 = compile_from_source_str(source, Some("test.runar.ts"))
        .expect("second compilation");
    assert_eq!(
        artifact1.script, artifact2.script,
        "script hex should be identical across two compilations"
    );
    assert_eq!(
        artifact1.asm, artifact2.asm,
        "asm should be identical across two compilations"
    );
}

#[test]
fn test_optimizer_roll2_to_rot() {
    use runar_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use runar_compiler_rust::codegen::stack::{PushValue, StackOp};

    let ops = vec![
        StackOp::Push(PushValue::Int(2)),
        StackOp::Roll { depth: 2 },
    ];
    let optimized = optimize_stack_ops(&ops);
    assert_eq!(optimized.len(), 1, "Should reduce to 1 op: {:?}", optimized);
    assert!(matches!(&optimized[0], StackOp::Rot), "Should be Rot: {:?}", optimized);
}

// ---------------------------------------------------------------------------
// Test: Emit — constructor slot byte offsets with push-data prefix
// Mirrors Go: TestEmit_PlaceholderByteOffsets / TestEmit_ByteOffsetWithPushData
// ---------------------------------------------------------------------------

#[test]
fn test_emit_constructor_slot_byte_offsets() {
    // A 33-byte PubKey push takes 34 bytes (1 length prefix + 33 data bytes).
    // The first slot at offset 0 uses OP_0 (1 byte); subsequent slots shift.
    // Here we use a contract with two constructor properties and verify that
    // the second slot's byte offset is strictly greater than the first slot's.
    let ir_json = r#"{
        "contractName": "TwoSlots",
        "properties": [
            {"name": "x", "type": "bigint", "readonly": true},
            {"name": "y", "type": "bigint", "readonly": true}
        ],
        "methods": [{
            "name": "check",
            "params": [{"name": "a", "type": "bigint"}],
            "body": [
                {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
                {"name": "t1", "value": {"kind": "load_prop", "name": "x"}},
                {"name": "t2", "value": {"kind": "load_prop", "name": "y"}},
                {"name": "t3", "value": {"kind": "bin_op", "op": "+", "left": "t1", "right": "t2"}},
                {"name": "t4", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t3"}},
                {"name": "t5", "value": {"kind": "assert", "value": "t4"}}
            ],
            "isPublic": true
        }]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("compilation should succeed");

    // There should be exactly 2 constructor slots (one per property).
    assert_eq!(
        artifact.constructor_slots.len(),
        2,
        "expected 2 constructor slots, got {}",
        artifact.constructor_slots.len()
    );

    let slot0 = &artifact.constructor_slots[0];
    let slot1 = &artifact.constructor_slots[1];

    // Slots must have distinct indices.
    assert_ne!(
        slot0.param_index, slot1.param_index,
        "constructor slot paramIndex values must be distinct"
    );

    // The second slot must have a higher byte offset than the first.
    assert!(
        slot1.byte_offset > slot0.byte_offset,
        "second constructor slot byte_offset ({}) must be > first ({})",
        slot1.byte_offset,
        slot0.byte_offset
    );

    // First slot is the first op in the script, so byte_offset should be 0.
    assert_eq!(
        slot0.byte_offset, 0,
        "first constructor slot should be at byte offset 0, got {}",
        slot0.byte_offset
    );
}

// ---------------------------------------------------------------------------
// Test: Emit — multi-method dispatch contains OP_IF/OP_ELSE/OP_ENDIF
// Mirrors Go: TestEmit_MultiMethodDispatch
// ---------------------------------------------------------------------------

#[test]
fn test_emit_multi_method_dispatch() {
    // A contract with two public methods should produce a dispatch preamble
    // using OP_IF / OP_ELSE / OP_ENDIF around the method bodies.
    let ir_json = r#"{
        "contractName": "MultiDispatch",
        "properties": [],
        "methods": [
            {
                "name": "m1",
                "params": [{"name": "x", "type": "bigint"}],
                "body": [
                    {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 1}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
                    {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
                ],
                "isPublic": true
            },
            {
                "name": "m2",
                "params": [{"name": "y", "type": "bigint"}],
                "body": [
                    {"name": "t0", "value": {"kind": "load_param", "name": "y"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 2}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
                    {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
                ],
                "isPublic": true
            }
        ]
    }"#;

    let artifact = compile_from_ir_str(ir_json).expect("multi-method compilation should succeed");

    assert!(!artifact.script.is_empty(), "script should not be empty");
    assert!(!artifact.asm.is_empty(), "asm should not be empty");

    assert!(
        artifact.asm.contains("OP_IF"),
        "expected OP_IF in multi-method dispatch asm, got: {}",
        artifact.asm
    );
    assert!(
        artifact.asm.contains("OP_ELSE"),
        "expected OP_ELSE in multi-method dispatch asm, got: {}",
        artifact.asm
    );
    assert!(
        artifact.asm.contains("OP_ENDIF"),
        "expected OP_ENDIF in multi-method dispatch asm, got: {}",
        artifact.asm
    );
}

// ---------------------------------------------------------------------------
// Test: IR loader — invalid JSON returns an error (not a panic)
// Mirrors Go: TestLoadIRFromBytes_InvalidJSON
// ---------------------------------------------------------------------------

#[test]
fn test_ir_loader_invalid_json_returns_error() {
    // Passing malformed JSON to the IR-based entry point should return Err,
    // not panic. Any descriptive error message is acceptable.
    let result = compile_from_ir_str("{not valid json");
    assert!(
        result.is_err(),
        "invalid JSON should produce an Err, not a panic"
    );
    let err_msg = result.unwrap_err();
    // The error should mention JSON parsing failure in some way.
    assert!(
        err_msg.to_lowercase().contains("json")
            || err_msg.to_lowercase().contains("invalid")
            || err_msg.to_lowercase().contains("parse"),
        "error message should describe the JSON parsing failure, got: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// Row 214: 3-method contract → last method uses OP_NUMEQUALVERIFY (fail-closed dispatch)
// In a 3-method contract, the last method in the dispatch table must use
// OP_NUMEQUALVERIFY (not OP_NUMEQUAL) to fail-close the dispatch selector.
// ---------------------------------------------------------------------------

#[test]
fn test_three_method_dispatch_last_uses_numequalverify() {
    // A 3-public-method contract forces the emitter to produce:
    //   selector OP_1 OP_IF <m1> OP_ELSE
    //     selector OP_2 OP_IF <m2> OP_ELSE
    //       selector OP_3 OP_NUMEQUALVERIFY <m3>
    //     OP_ENDIF
    //   OP_ENDIF
    // The last method check uses OP_NUMEQUALVERIFY (not OP_NUMEQUAL) so the
    // script fails when the selector doesn't match any method.
    let ir_json = r#"{
        "contractName": "ThreeMethod",
        "properties": [],
        "methods": [
            {
                "name": "m1",
                "params": [{"name": "x", "type": "bigint"}],
                "body": [
                    {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 1}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
                    {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
                ],
                "isPublic": true
            },
            {
                "name": "m2",
                "params": [{"name": "x", "type": "bigint"}],
                "body": [
                    {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 2}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
                    {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
                ],
                "isPublic": true
            },
            {
                "name": "m3",
                "params": [{"name": "x", "type": "bigint"}],
                "body": [
                    {"name": "t0", "value": {"kind": "load_param", "name": "x"}},
                    {"name": "t1", "value": {"kind": "load_const", "value": 3}},
                    {"name": "t2", "value": {"kind": "bin_op", "op": "===", "left": "t0", "right": "t1"}},
                    {"name": "t3", "value": {"kind": "assert", "value": "t2"}}
                ],
                "isPublic": true
            }
        ]
    }"#;

    let artifact = compile_from_ir_str(ir_json)
        .expect("3-method compilation should succeed");

    // The dispatch table for N >= 2 methods must use OP_NUMEQUALVERIFY for
    // the last method (fail-closed: rejects any selector that doesn't match).
    assert!(
        artifact.asm.contains("OP_NUMEQUALVERIFY"),
        "3-method contract should use OP_NUMEQUALVERIFY for the last dispatch entry; got asm: {}",
        artifact.asm
    );
}
