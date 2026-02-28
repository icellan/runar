//! Integration tests for the TSOP Rust compiler.

use tsop_compiler_rust::{compile_from_ir_str, compile_from_source_str};

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
    assert_eq!(artifact.version, "tsop-v0.1.0");

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
    use tsop_compiler_rust::codegen::emit::{encode_push_int, encode_script_number};

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
        "tsop-v0.1.0"
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
    use tsop_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use tsop_compiler_rust::codegen::stack::StackOp;

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
    use tsop_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use tsop_compiler_rust::codegen::stack::StackOp;

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
    use tsop_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use tsop_compiler_rust::codegen::stack::StackOp;

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
        "basic-p2pkh",
        "boolean-logic",
        "bounded-loop",
        "if-else",
        "multi-method",
        "stateful",
    ];

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

        // Compare against golden expected-script.hex
        if let Some(expected_hex) = load_expected_script_hex(dir) {
            assert_eq!(
                artifact.script, expected_hex,
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
    use tsop_compiler_rust::codegen::emit::encode_push_data;

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
    use tsop_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use tsop_compiler_rust::codegen::stack::{PushValue, StackOp};

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
    use tsop_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use tsop_compiler_rust::codegen::stack::StackOp;

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
    use tsop_compiler_rust::codegen::optimizer::optimize_stack_ops;
    use tsop_compiler_rust::codegen::stack::{PushValue, StackOp};

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
// Source compilation tests (.tsop.ts → Bitcoin Script via native SWC frontend)
// ---------------------------------------------------------------------------

fn conformance_source(test_name: &str) -> String {
    let path = conformance_dir()
        .join(test_name)
        .join(format!("{}.tsop.ts", test_name));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read source {}: {}", path.display(), e))
}

fn example_source(contract_dir: &str, file_name: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join(contract_dir)
        .join(file_name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read example {}: {}", path.display(), e))
}

#[test]
fn test_source_compile_p2pkh() {
    let source = conformance_source("basic-p2pkh");
    let artifact = compile_from_source_str(&source, Some("basic-p2pkh.tsop.ts"))
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
    let artifact = compile_from_source_str(&source, Some("arithmetic.tsop.ts"))
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
    let artifact = compile_from_source_str(&source, Some("boolean-logic.tsop.ts"))
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
    let artifact = compile_from_source_str(&source, Some("if-else.tsop.ts"))
        .expect("source compilation should succeed");

    assert!(artifact.asm.contains("OP_IF"), "expected OP_IF in ASM");
}

#[test]
fn test_source_compile_bounded_loop() {
    let source = conformance_source("bounded-loop");
    let artifact = compile_from_source_str(&source, Some("bounded-loop.tsop.ts"))
        .expect("source compilation should succeed");

    assert!(!artifact.script.is_empty());
}

#[test]
fn test_source_compile_multi_method() {
    let source = conformance_source("multi-method");
    let artifact = compile_from_source_str(&source, Some("multi-method.tsop.ts"))
        .expect("source compilation should succeed");

    assert!(
        artifact.asm.contains("OP_IF"),
        "expected OP_IF for dispatch table"
    );
}

#[test]
fn test_source_compile_stateful() {
    let source = conformance_source("stateful");
    let artifact = compile_from_source_str(&source, Some("stateful.tsop.ts"))
        .expect("source compilation should succeed");

    assert!(
        artifact.asm.contains("OP_HASH256"),
        "expected OP_HASH256 for state hashing"
    );
}

#[test]
fn test_source_compile_all_conformance() {
    let test_dirs = [
        "arithmetic",
        "basic-p2pkh",
        "boolean-logic",
        "bounded-loop",
        "if-else",
        "multi-method",
        "stateful",
    ];

    for dir in &test_dirs {
        let source = conformance_source(dir);
        let artifact = compile_from_source_str(&source, Some(&format!("{}.tsop.ts", dir)))
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

        // Compare against golden expected-script.hex
        if let Some(expected_hex) = load_expected_script_hex(dir) {
            assert_eq!(
                artifact.script, expected_hex,
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
    let source = example_source("p2pkh", "P2PKH.tsop.ts");
    let artifact = compile_from_source_str(&source, Some("P2PKH.tsop.ts"))
        .expect("example P2PKH should compile");

    assert_eq!(artifact.contract_name, "P2PKH");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_source_compile_example_escrow() {
    let source = example_source("escrow", "Escrow.tsop.ts");
    let artifact = compile_from_source_str(&source, Some("Escrow.tsop.ts"))
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
    let source_artifact = compile_from_source_str(&source, Some("basic-p2pkh.tsop.ts"))
        .expect("source compilation");

    // Both should produce P2PKH
    assert_eq!(ir_artifact.contract_name, source_artifact.contract_name);

    // Both should produce non-empty scripts
    assert!(!ir_artifact.script.is_empty());
    assert!(!source_artifact.script.is_empty());

    println!("IR hex:     {}", ir_artifact.script);
    println!("Source hex: {}", source_artifact.script);
}
