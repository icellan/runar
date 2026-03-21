//! Pass 6: Emit -- converts Stack IR to Bitcoin Script bytes (hex string).
//!
//! Walks the StackOp list and encodes each operation as one or more Bitcoin
//! Script opcodes, producing both a hex-encoded script and a human-readable
//! ASM representation.

use serde::{Deserialize, Serialize};

use super::opcodes::opcode_byte;
use super::stack::{PushValue, StackMethod, StackOp};

// ---------------------------------------------------------------------------
// ConstructorSlot
// ---------------------------------------------------------------------------

/// Records the byte offset of a constructor parameter placeholder in the
/// emitted script. The SDK uses these offsets to splice in real values at
/// deployment time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructorSlot {
    #[serde(rename = "paramIndex")]
    pub param_index: usize,
    #[serde(rename = "byteOffset")]
    pub byte_offset: usize,
}

// ---------------------------------------------------------------------------
// EmitResult
// ---------------------------------------------------------------------------

/// The output of the emission pass.
#[derive(Debug, Clone)]
pub struct EmitResult {
    pub script_hex: String,
    pub script_asm: String,
    pub constructor_slots: Vec<ConstructorSlot>,
    pub code_separator_index: i64,
    pub code_separator_indices: Vec<usize>,
}

// ---------------------------------------------------------------------------
// Emit context
// ---------------------------------------------------------------------------

struct EmitContext {
    hex_parts: Vec<String>,
    asm_parts: Vec<String>,
    byte_length: usize,
    constructor_slots: Vec<ConstructorSlot>,
    code_separator_index: i64,
    code_separator_indices: Vec<usize>,
}

impl EmitContext {
    fn new() -> Self {
        EmitContext {
            hex_parts: Vec::new(),
            asm_parts: Vec::new(),
            byte_length: 0,
            constructor_slots: Vec::new(),
            code_separator_index: -1,
            code_separator_indices: Vec::new(),
        }
    }

    fn append_hex(&mut self, hex: &str) {
        self.byte_length += hex.len() / 2;
        self.hex_parts.push(hex.to_string());
    }

    fn emit_opcode(&mut self, name: &str) -> Result<(), String> {
        let byte = opcode_byte(name)
            .ok_or_else(|| format!("unknown opcode: {}", name))?;
        if name == "OP_CODESEPARATOR" {
            self.code_separator_index = self.byte_length as i64;
            self.code_separator_indices.push(self.byte_length);
        }
        self.append_hex(&format!("{:02x}", byte));
        self.asm_parts.push(name.to_string());
        Ok(())
    }

    fn emit_push(&mut self, value: &PushValue) {
        let (h, a) = encode_push_value(value);
        self.append_hex(&h);
        self.asm_parts.push(a);
    }

    fn emit_placeholder(&mut self, param_index: usize, _param_name: &str) {
        let byte_offset = self.byte_length;
        self.append_hex("00"); // OP_0 placeholder byte
        self.asm_parts.push("OP_0".to_string());
        self.constructor_slots.push(ConstructorSlot {
            param_index,
            byte_offset,
        });
    }

    fn get_hex(&self) -> String {
        self.hex_parts.join("")
    }

    fn get_asm(&self) -> String {
        self.asm_parts.join(" ")
    }
}

// ---------------------------------------------------------------------------
// Script number encoding
// ---------------------------------------------------------------------------

/// Encode an i128 as a Bitcoin Script number (little-endian, sign-magnitude).
/// Bitcoin Script numbers can be up to 2^252, so i128 is needed.
pub fn encode_script_number(n: i128) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }

    let negative = n < 0;
    let mut abs = if negative { (-n) as u128 } else { n as u128 };

    let mut bytes = Vec::new();
    while abs > 0 {
        bytes.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    let last_byte = *bytes.last().unwrap();
    if last_byte & 0x80 != 0 {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let len = bytes.len();
        bytes[len - 1] = last_byte | 0x80;
    }

    bytes
}

// ---------------------------------------------------------------------------
// Push data encoding
// ---------------------------------------------------------------------------

/// Encode raw bytes as a Bitcoin Script push-data operation.
pub fn encode_push_data(data: &[u8]) -> Vec<u8> {
    let len = data.len();

    if len == 0 {
        return vec![0x00]; // OP_0
    }

    // MINIMALDATA: single-byte values 1-16 must use OP_1..OP_16, 0x81 must use OP_1NEGATE.
    // Note: 0x00 is NOT converted to OP_0 because OP_0 pushes empty [] not [0x00].
    if len == 1 {
        let b = data[0];
        if b >= 1 && b <= 16 {
            return vec![0x50 + b]; // OP_1 through OP_16
        }
        if b == 0x81 {
            return vec![0x4f]; // OP_1NEGATE
        }
    }

    if len <= 75 {
        let mut result = vec![len as u8];
        result.extend_from_slice(data);
        return result;
    }

    if len <= 255 {
        let mut result = vec![0x4c, len as u8]; // OP_PUSHDATA1
        result.extend_from_slice(data);
        return result;
    }

    if len <= 65535 {
        let mut result = vec![0x4d, (len & 0xff) as u8, ((len >> 8) & 0xff) as u8]; // OP_PUSHDATA2
        result.extend_from_slice(data);
        return result;
    }

    // OP_PUSHDATA4
    let mut result = vec![
        0x4e,
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        ((len >> 24) & 0xff) as u8,
    ];
    result.extend_from_slice(data);
    result
}

/// Encode a push value to hex and asm strings.
fn encode_push_value(value: &PushValue) -> (String, String) {
    match value {
        PushValue::Bool(b) => {
            if *b {
                ("51".to_string(), "OP_TRUE".to_string())
            } else {
                ("00".to_string(), "OP_FALSE".to_string())
            }
        }
        PushValue::Int(n) => encode_push_int(*n),
        PushValue::Bytes(bytes) => {
            let encoded = encode_push_data(bytes);
            let h = hex::encode(&encoded);
            if bytes.is_empty() {
                (h, "OP_0".to_string())
            } else {
                (h, format!("<{}>", hex::encode(bytes)))
            }
        }
    }
}

/// Encode an integer push, using small-integer opcodes where possible.
pub fn encode_push_int(n: i128) -> (String, String) {
    if n == 0 {
        return ("00".to_string(), "OP_0".to_string());
    }

    if n == -1 {
        return ("4f".to_string(), "OP_1NEGATE".to_string());
    }

    if n >= 1 && n <= 16 {
        let opcode = 0x50 + n as u8;
        return (format!("{:02x}", opcode), format!("OP_{}", n));
    }

    let num_bytes = encode_script_number(n);
    let encoded = encode_push_data(&num_bytes);
    (hex::encode(&encoded), format!("<{}>", hex::encode(&num_bytes)))
}

// ---------------------------------------------------------------------------
// Emit a single StackOp
// ---------------------------------------------------------------------------

fn emit_stack_op(op: &StackOp, ctx: &mut EmitContext) -> Result<(), String> {
    match op {
        StackOp::Push(value) => {
            ctx.emit_push(value);
            Ok(())
        }
        StackOp::Dup => ctx.emit_opcode("OP_DUP"),
        StackOp::Swap => ctx.emit_opcode("OP_SWAP"),
        StackOp::Roll { .. } => ctx.emit_opcode("OP_ROLL"),
        StackOp::Pick { .. } => ctx.emit_opcode("OP_PICK"),
        StackOp::Drop => ctx.emit_opcode("OP_DROP"),
        StackOp::Nip => ctx.emit_opcode("OP_NIP"),
        StackOp::Over => ctx.emit_opcode("OP_OVER"),
        StackOp::Rot => ctx.emit_opcode("OP_ROT"),
        StackOp::Tuck => ctx.emit_opcode("OP_TUCK"),
        StackOp::Opcode(code) => ctx.emit_opcode(code),
        StackOp::If {
            then_ops,
            else_ops,
        } => emit_if(then_ops, else_ops, ctx),
        StackOp::Placeholder {
            param_index,
            param_name,
        } => {
            ctx.emit_placeholder(*param_index, param_name);
            Ok(())
        }
        StackOp::PushCodeSepIndex => {
            // Push the codeSeparatorIndex as a numeric constant.
            let idx = if ctx.code_separator_index < 0 {
                0i64
            } else {
                ctx.code_separator_index
            };
            ctx.emit_push(&PushValue::Int(idx as i128));
            Ok(())
        }
    }
}

fn emit_if(
    then_ops: &[StackOp],
    else_ops: &[StackOp],
    ctx: &mut EmitContext,
) -> Result<(), String> {
    ctx.emit_opcode("OP_IF")?;

    for op in then_ops {
        emit_stack_op(op, ctx)?;
    }

    if !else_ops.is_empty() {
        ctx.emit_opcode("OP_ELSE")?;
        for op in else_ops {
            emit_stack_op(op, ctx)?;
        }
    }

    ctx.emit_opcode("OP_ENDIF")
}

// ---------------------------------------------------------------------------
// Peephole optimization
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Emit a slice of StackMethods as Bitcoin Script hex and ASM.
///
/// For contracts with multiple public methods, generates a method dispatch
/// preamble using OP_IF/OP_ELSE chains.
///
/// Note: peephole optimization (VERIFY combinations, SWAP elimination) is
/// handled by `optimize_stack_ops` in optimizer.rs, which runs before emit.
pub fn emit(methods: &[StackMethod]) -> Result<EmitResult, String> {
    let mut ctx = EmitContext::new();

    // Filter to public methods (exclude constructor)
    let public_methods: Vec<StackMethod> = methods
        .iter()
        .filter(|m| m.name != "constructor")
        .cloned()
        .collect();

    if public_methods.is_empty() {
        return Ok(EmitResult {
            script_hex: String::new(),
            script_asm: String::new(),
            constructor_slots: Vec::new(),
            code_separator_index: -1,
            code_separator_indices: Vec::new(),
        });
    }

    if public_methods.len() == 1 {
        for op in &public_methods[0].ops {
            emit_stack_op(op, &mut ctx)?;
        }
    } else {
        let refs: Vec<&StackMethod> = public_methods.iter().collect();
        emit_method_dispatch(&refs, &mut ctx)?;
    }

    Ok(EmitResult {
        script_hex: ctx.get_hex(),
        script_asm: ctx.get_asm(),
        constructor_slots: ctx.constructor_slots,
        code_separator_index: ctx.code_separator_index,
        code_separator_indices: ctx.code_separator_indices,
    })
}

fn emit_method_dispatch(
    methods: &[&StackMethod],
    ctx: &mut EmitContext,
) -> Result<(), String> {
    for (i, method) in methods.iter().enumerate() {
        let is_last = i == methods.len() - 1;

        if !is_last {
            ctx.emit_opcode("OP_DUP")?;
            ctx.emit_push(&PushValue::Int(i as i128));
            ctx.emit_opcode("OP_NUMEQUAL")?;
            ctx.emit_opcode("OP_IF")?;
            ctx.emit_opcode("OP_DROP")?;
        } else {
            // Last method — verify the index matches (fail-closed for invalid selectors)
            ctx.emit_push(&PushValue::Int(i as i128));
            ctx.emit_opcode("OP_NUMEQUALVERIFY")?;
        }

        for op in &method.ops {
            emit_stack_op(op, ctx)?;
        }

        if !is_last {
            ctx.emit_opcode("OP_ELSE")?;
        }
    }

    // Close nested OP_IF/OP_ELSE blocks
    for _ in 0..methods.len() - 1 {
        ctx.emit_opcode("OP_ENDIF")?;
    }

    Ok(())
}

/// Emit a single method's ops. Useful for testing.
pub fn emit_method(method: &StackMethod) -> Result<EmitResult, String> {
    let mut ctx = EmitContext::new();
    for op in &method.ops {
        emit_stack_op(op, &mut ctx)?;
    }
    Ok(EmitResult {
        script_hex: ctx.get_hex(),
        script_asm: ctx.get_asm(),
        constructor_slots: ctx.constructor_slots,
        code_separator_index: ctx.code_separator_index,
        code_separator_indices: ctx.code_separator_indices,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_placeholder_produces_constructor_slot() {
        let method = StackMethod {
            name: "unlock".to_string(),
            ops: vec![StackOp::Placeholder {
                param_index: 0,
                param_name: "pubKeyHash".to_string(),
            }],
            max_stack_depth: 1,
        };

        let result = emit_method(&method).expect("emit should succeed");
        assert_eq!(
            result.constructor_slots.len(),
            1,
            "should produce exactly one constructor slot"
        );
        assert_eq!(result.constructor_slots[0].param_index, 0);
        assert_eq!(result.constructor_slots[0].byte_offset, 0);
    }

    #[test]
    fn test_multiple_placeholders_produce_distinct_byte_offsets() {
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![
                StackOp::Placeholder {
                    param_index: 0,
                    param_name: "a".to_string(),
                },
                StackOp::Placeholder {
                    param_index: 1,
                    param_name: "b".to_string(),
                },
            ],
            max_stack_depth: 2,
        };

        let result = emit_method(&method).expect("emit should succeed");
        assert_eq!(
            result.constructor_slots.len(),
            2,
            "should produce two constructor slots"
        );

        // First placeholder at byte 0
        assert_eq!(result.constructor_slots[0].param_index, 0);
        assert_eq!(result.constructor_slots[0].byte_offset, 0);

        // Second placeholder at byte 1 (after the first OP_0 byte)
        assert_eq!(result.constructor_slots[1].param_index, 1);
        assert_eq!(result.constructor_slots[1].byte_offset, 1);

        // Byte offsets should be distinct
        assert_ne!(
            result.constructor_slots[0].byte_offset,
            result.constructor_slots[1].byte_offset
        );
    }

    #[test]
    fn test_placeholder_byte_offset_position_is_op_0() {
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![
                StackOp::Push(PushValue::Int(42)), // some bytes before
                StackOp::Placeholder {
                    param_index: 0,
                    param_name: "x".to_string(),
                },
            ],
            max_stack_depth: 2,
        };

        let result = emit_method(&method).expect("emit should succeed");
        assert_eq!(result.constructor_slots.len(), 1);

        let slot = &result.constructor_slots[0];
        let hex = &result.script_hex;

        // The byte at the placeholder offset should be "00" (OP_0)
        let byte_hex = &hex[slot.byte_offset * 2..slot.byte_offset * 2 + 2];
        assert_eq!(
            byte_hex, "00",
            "expected OP_0 at placeholder byte offset {}, got '{}' in hex '{}'",
            slot.byte_offset, byte_hex, hex
        );
    }

    #[test]
    fn test_emit_single_method_produces_hex_and_asm() {
        use super::super::optimizer::optimize_stack_ops;

        let method = StackMethod {
            name: "check".to_string(),
            ops: vec![
                StackOp::Push(PushValue::Int(42)),
                StackOp::Opcode("OP_NUMEQUAL".to_string()),
                StackOp::Opcode("OP_VERIFY".to_string()),
            ],
            max_stack_depth: 1,
        };

        // Apply peephole optimization before emit (as the compiler pipeline does)
        let optimized_method = StackMethod {
            name: method.name.clone(),
            ops: optimize_stack_ops(&method.ops),
            max_stack_depth: method.max_stack_depth,
        };

        let result = emit(&[optimized_method]).expect("emit should succeed");
        assert!(!result.script_hex.is_empty(), "hex should not be empty");
        assert!(!result.script_asm.is_empty(), "asm should not be empty");
        assert!(
            result.script_asm.contains("OP_NUMEQUALVERIFY"),
            "standalone peephole optimizer should combine OP_NUMEQUAL + OP_VERIFY into OP_NUMEQUALVERIFY, got: {}",
            result.script_asm
        );
    }

    #[test]
    fn test_emit_empty_methods_produces_empty_output() {
        let result = emit(&[]).expect("emit with no methods should succeed");
        assert!(
            result.script_hex.is_empty(),
            "empty methods should produce empty hex"
        );
        assert!(
            result.constructor_slots.is_empty(),
            "empty methods should produce no constructor slots"
        );
    }

    #[test]
    fn test_emit_push_bool_values() {
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![
                StackOp::Push(PushValue::Bool(true)),
                StackOp::Push(PushValue::Bool(false)),
            ],
            max_stack_depth: 2,
        };

        let result = emit_method(&method).expect("emit should succeed");
        // OP_TRUE = 0x51, OP_FALSE = 0x00
        assert!(
            result.script_hex.starts_with("51"),
            "true should emit 0x51, got: {}",
            result.script_hex
        );
        assert!(
            result.script_hex.ends_with("00"),
            "false should emit 0x00, got: {}",
            result.script_hex
        );
        assert!(result.script_asm.contains("OP_TRUE"));
        assert!(result.script_asm.contains("OP_FALSE"));
    }

    // -----------------------------------------------------------------------
    // Test: byte offset accounts for push-data (placeholder after push has offset > 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_byte_offset_with_push_data() {
        // Push the number 17 — encoded as 0x01 0x11 (2 bytes: length prefix + value)
        // Then a placeholder at offset 2
        let method = StackMethod {
            name: "check".to_string(),
            ops: vec![
                StackOp::Push(PushValue::Int(17)), // 2 bytes: 01 11
                StackOp::Placeholder {
                    param_index: 0,
                    param_name: "x".to_string(),
                },
                StackOp::Opcode("OP_ADD".to_string()),
            ],
            max_stack_depth: 2,
        };

        let result = emit_method(&method).expect("emit should succeed");
        assert_eq!(
            result.constructor_slots.len(),
            1,
            "expected 1 constructor slot"
        );

        let slot = &result.constructor_slots[0];
        // Push 17 takes 2 bytes (0x01 length prefix + 0x11 value), so placeholder is at offset 2
        assert_eq!(
            slot.byte_offset, 2,
            "expected byteOffset=2 (after push 17 = 2 bytes), got {}",
            slot.byte_offset
        );
    }

    // -----------------------------------------------------------------------
    // Test: simple opcode sequence produces correct hex
    // -----------------------------------------------------------------------

    #[test]
    fn test_simple_sequence_hex() {
        let method = StackMethod {
            name: "check".to_string(),
            ops: vec![
                StackOp::Opcode("OP_DUP".to_string()),
                StackOp::Opcode("OP_HASH160".to_string()),
            ],
            max_stack_depth: 1,
        };

        let result = emit_method(&method).expect("emit should succeed");
        // OP_DUP = 0x76, OP_HASH160 = 0xa9
        assert_eq!(
            result.script_hex, "76a9",
            "expected hex '76a9' for DUP+HASH160, got: {}",
            result.script_hex
        );
    }

    // -----------------------------------------------------------------------
    // Test: CHECKSIG + VERIFY becomes CHECKSIGVERIFY via peephole optimization
    // -----------------------------------------------------------------------

    #[test]
    fn test_peephole_optimization_applied() {
        use super::super::optimizer::optimize_stack_ops;

        let ops = vec![
            StackOp::Opcode("OP_CHECKSIG".to_string()),
            StackOp::Opcode("OP_VERIFY".to_string()),
            StackOp::Opcode("OP_1".to_string()),
        ];

        let optimized_ops = optimize_stack_ops(&ops);
        let method = StackMethod {
            name: "check".to_string(),
            ops: optimized_ops,
            max_stack_depth: 1,
        };

        let result = emit_method(&method).expect("emit should succeed");

        // After peephole: CHECKSIG + VERIFY -> CHECKSIGVERIFY (0xad), then OP_1 (0x51)
        assert_eq!(
            result.script_hex, "ad51",
            "expected 'ad51' (CHECKSIGVERIFY + OP_1) after peephole, got: {}",
            result.script_hex
        );
        assert!(
            result.script_asm.contains("OP_CHECKSIGVERIFY"),
            "expected OP_CHECKSIGVERIFY in ASM, got: {}",
            result.script_asm
        );
    }

    // -----------------------------------------------------------------------
    // Test: multi-method contract emits OP_IF / OP_ELSE / OP_ENDIF
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_method_dispatch_produces_if_else() {
        use super::super::stack::lower_to_stack;
        use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFValue};

        let program = ANFProgram {
            contract_name: "Multi".to_string(),
            properties: vec![],
            methods: vec![
                ANFMethod {
                    name: "constructor".to_string(),
                    params: vec![],
                    body: vec![],
                    is_public: false,
                },
                ANFMethod {
                    name: "m1".to_string(),
                    params: vec![ANFParam {
                        name: "x".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                    body: vec![
                        ANFBinding {
                            name: "t0".to_string(),
                            value: ANFValue::LoadParam { name: "x".to_string() },
                        },
                        ANFBinding {
                            name: "t1".to_string(),
                            value: ANFValue::LoadConst {
                                value: serde_json::Value::Number(serde_json::Number::from(1)),
                            },
                        },
                        ANFBinding {
                            name: "t2".to_string(),
                            value: ANFValue::BinOp {
                                op: "===".to_string(),
                                left: "t0".to_string(),
                                right: "t1".to_string(),
                                result_type: None,
                            },
                        },
                        ANFBinding {
                            name: "t3".to_string(),
                            value: ANFValue::Assert { value: "t2".to_string() },
                        },
                    ],
                    is_public: true,
                },
                ANFMethod {
                    name: "m2".to_string(),
                    params: vec![ANFParam {
                        name: "y".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                    body: vec![
                        ANFBinding {
                            name: "t0".to_string(),
                            value: ANFValue::LoadParam { name: "y".to_string() },
                        },
                        ANFBinding {
                            name: "t1".to_string(),
                            value: ANFValue::LoadConst {
                                value: serde_json::Value::Number(serde_json::Number::from(2)),
                            },
                        },
                        ANFBinding {
                            name: "t2".to_string(),
                            value: ANFValue::BinOp {
                                op: "===".to_string(),
                                left: "t0".to_string(),
                                right: "t1".to_string(),
                                result_type: None,
                            },
                        },
                        ANFBinding {
                            name: "t3".to_string(),
                            value: ANFValue::Assert { value: "t2".to_string() },
                        },
                    ],
                    is_public: true,
                },
            ],
        };

        let methods = lower_to_stack(&program).expect("lower_to_stack should succeed");

        // Apply peephole optimization as the compiler pipeline does
        use super::super::optimizer::optimize_stack_ops;
        let optimized: Vec<StackMethod> = methods
            .iter()
            .map(|m| StackMethod {
                name: m.name.clone(),
                ops: optimize_stack_ops(&m.ops),
                max_stack_depth: m.max_stack_depth,
            })
            .collect();

        let result = emit(&optimized).expect("emit should succeed");

        // Multi-method dispatch should emit OP_IF / OP_ELSE / OP_ENDIF
        assert!(
            result.script_asm.contains("OP_IF"),
            "expected OP_IF in multi-method dispatch, got: {}",
            result.script_asm
        );
        assert!(
            result.script_asm.contains("OP_ELSE"),
            "expected OP_ELSE in multi-method dispatch, got: {}",
            result.script_asm
        );
        assert!(
            result.script_asm.contains("OP_ENDIF"),
            "expected OP_ENDIF in multi-method dispatch, got: {}",
            result.script_asm
        );
    }

    // -----------------------------------------------------------------------
    // Test: byte offset accounts for preceding single-byte opcodes
    // Mirrors Go TestEmit_ByteOffsetAccountsForPrecedingOpcodes
    // -----------------------------------------------------------------------

    #[test]
    fn test_byte_offset_accounts_for_preceding_opcodes() {
        // OP_DUP (1 byte: 0x76) + OP_HASH160 (1 byte: 0xa9) before Placeholder
        // => placeholder should be at byte offset 2
        let method = StackMethod {
            name: "check".to_string(),
            ops: vec![
                StackOp::Opcode("OP_DUP".to_string()),       // 1 byte
                StackOp::Opcode("OP_HASH160".to_string()),   // 1 byte
                StackOp::Placeholder {
                    param_index: 0,
                    param_name: "pubKeyHash".to_string(),
                },
                StackOp::Opcode("OP_EQUALVERIFY".to_string()),
                StackOp::Opcode("OP_CHECKSIG".to_string()),
            ],
            max_stack_depth: 2,
        };

        let result = emit_method(&method).expect("emit should succeed");
        assert_eq!(result.constructor_slots.len(), 1, "expected 1 constructor slot");

        let slot = &result.constructor_slots[0];
        // OP_DUP (1 byte) + OP_HASH160 (1 byte) = 2 bytes before placeholder
        assert_eq!(
            slot.byte_offset, 2,
            "expected byteOffset=2 (after OP_DUP + OP_HASH160), got {}",
            slot.byte_offset
        );
    }

    // -----------------------------------------------------------------------
    // Test: full P2PKH pipeline produces non-empty script and constructor slots
    // Mirrors Go TestEmit_FullP2PKH
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_p2pkh() {
        use super::super::stack::lower_to_stack;
        use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

        let program = ANFProgram {
            contract_name: "P2PKH".to_string(),
            properties: vec![ANFProperty {
                name: "pubKeyHash".to_string(),
                prop_type: "Addr".to_string(),
                readonly: true,
                initial_value: None,
            }],
            methods: vec![ANFMethod {
                name: "unlock".to_string(),
                params: vec![
                    ANFParam { name: "sig".to_string(), param_type: "Sig".to_string() },
                    ANFParam { name: "pubKey".to_string(), param_type: "PubKey".to_string() },
                ],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "pubKey".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "hash160".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::LoadProp { name: "pubKeyHash".to_string() },
                    },
                    ANFBinding {
                        name: "t3".to_string(),
                        value: ANFValue::BinOp {
                            op: "===".to_string(),
                            left: "t1".to_string(),
                            right: "t2".to_string(),
                            result_type: Some("bytes".to_string()),
                        },
                    },
                    ANFBinding {
                        name: "t4".to_string(),
                        value: ANFValue::Assert { value: "t3".to_string() },
                    },
                    ANFBinding {
                        name: "t5".to_string(),
                        value: ANFValue::LoadParam { name: "sig".to_string() },
                    },
                    ANFBinding {
                        name: "t6".to_string(),
                        value: ANFValue::LoadParam { name: "pubKey".to_string() },
                    },
                    ANFBinding {
                        name: "t7".to_string(),
                        value: ANFValue::Call {
                            func: "checkSig".to_string(),
                            args: vec!["t5".to_string(), "t6".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t8".to_string(),
                        value: ANFValue::Assert { value: "t7".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let stack_methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let result = emit(&stack_methods).expect("emit should succeed");

        assert!(
            !result.script_hex.is_empty(),
            "P2PKH should produce non-empty script hex"
        );
        assert!(
            !result.constructor_slots.is_empty(),
            "P2PKH should have at least one constructor slot for pubKeyHash"
        );
    }

    // -----------------------------------------------------------------------
    // M10: integers 17+ use push prefix (not OP_17 opcode)
    // -----------------------------------------------------------------------

    #[test]
    fn test_m10_integer_17_uses_push_prefix_not_op17() {
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![StackOp::Push(PushValue::Int(17))],
            max_stack_depth: 1,
        };
        let result = emit_method(&method).expect("emit should succeed");
        // OP_17 would be 0x61. A push-data encoded 17 would be "0111" (length 1, value 0x11).
        assert!(
            !result.script_hex.starts_with("61"),
            "17 should NOT be encoded as OP_17 (0x61); OP_1..OP_16 are for 1–16 only. got: {}",
            result.script_hex
        );
        // Should use push-data prefix: 01 followed by the value byte 11
        assert!(
            result.script_hex.contains("11"),
            "17 (0x11) should appear in the script hex; got: {}",
            result.script_hex
        );
    }

    // -----------------------------------------------------------------------
    // M12: 256-byte data → OP_PUSHDATA2
    // 256-byte array → hex starts with "4d0001"
    // -----------------------------------------------------------------------

    #[test]
    fn test_m12_256_byte_data_uses_pushdata2() {
        let data = vec![0xabu8; 256];
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![StackOp::Push(PushValue::Bytes(data))],
            max_stack_depth: 1,
        };
        let result = emit_method(&method).expect("emit should succeed");
        // OP_PUSHDATA2 = 0x4d, followed by length in 2 bytes LE: 256 = 0x0001 LE = 00 01
        assert!(
            result.script_hex.starts_with("4d0001"),
            "256-byte push should use OP_PUSHDATA2 prefix '4d0001', got: {}",
            &result.script_hex[..result.script_hex.len().min(12)]
        );
    }

    // -----------------------------------------------------------------------
    // M19: sha256 contract has OP_SHA256 in ASM
    // -----------------------------------------------------------------------

    #[test]
    fn test_m19_sha256_contract_has_op_sha256_in_asm() {
        use super::super::stack::lower_to_stack;
        use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFValue};

        let program = ANFProgram {
            contract_name: "Sha256Test".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![ANFParam {
                    name: "data".to_string(),
                    param_type: "ByteString".to_string(),
                }],
                body: vec![
                    ANFBinding {
                        name: "t0".to_string(),
                        value: ANFValue::LoadParam { name: "data".to_string() },
                    },
                    ANFBinding {
                        name: "t1".to_string(),
                        value: ANFValue::Call {
                            func: "sha256".to_string(),
                            args: vec!["t0".to_string()],
                        },
                    },
                    ANFBinding {
                        name: "t2".to_string(),
                        value: ANFValue::Assert { value: "t1".to_string() },
                    },
                ],
                is_public: true,
            }],
        };

        let stack_methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let result = emit(&stack_methods).expect("emit should succeed");
        assert!(
            result.script_asm.contains("OP_SHA256"),
            "sha256() call should produce OP_SHA256 in ASM; got: {}",
            result.script_asm
        );
    }

    // -----------------------------------------------------------------------
    // M21: OP_DUP encodes 0x76
    // -----------------------------------------------------------------------

    #[test]
    fn test_m21_op_dup_encodes_0x76() {
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![StackOp::Dup],
            max_stack_depth: 1,
        };
        let result = emit_method(&method).expect("emit should succeed");
        assert_eq!(
            result.script_hex, "76",
            "OP_DUP should encode as 0x76; got: {}",
            result.script_hex
        );
    }

    // -----------------------------------------------------------------------
    // M22: OP_SWAP encodes 0x7c
    // -----------------------------------------------------------------------

    #[test]
    fn test_m22_op_swap_encodes_0x7c() {
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![StackOp::Swap],
            max_stack_depth: 2,
        };
        let result = emit_method(&method).expect("emit should succeed");
        assert_eq!(
            result.script_hex, "7c",
            "OP_SWAP should encode as 0x7c; got: {}",
            result.script_hex
        );
    }

    // -----------------------------------------------------------------------
    // M24: if without else → no OP_ELSE
    // -----------------------------------------------------------------------

    #[test]
    fn test_m24_if_without_else_no_op_else() {
        let method = StackMethod {
            name: "test".to_string(),
            ops: vec![StackOp::If {
                then_ops: vec![StackOp::Opcode("OP_DROP".to_string())],
                else_ops: vec![],
            }],
            max_stack_depth: 1,
        };
        let result = emit_method(&method).expect("emit should succeed");
        assert!(
            !result.script_asm.contains("OP_ELSE"),
            "if with empty else branch should NOT contain OP_ELSE; got asm: {}",
            result.script_asm
        );
        assert!(
            result.script_asm.contains("OP_IF"),
            "should still contain OP_IF; got asm: {}",
            result.script_asm
        );
    }

    // -----------------------------------------------------------------------
    // M25: single method → no dispatch (no OP_IF for method selection)
    // -----------------------------------------------------------------------

    #[test]
    fn test_m25_single_method_no_dispatch() {
        use super::super::stack::lower_to_stack;
        use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

        // A program with a single public method (plus constructor) — no method dispatch needed
        let program = ANFProgram {
            contract_name: "Single".to_string(),
            properties: vec![ANFProperty {
                name: "x".to_string(),
                prop_type: "bigint".to_string(),
                readonly: true,
                initial_value: None,
            }],
            methods: vec![
                ANFMethod {
                    name: "constructor".to_string(),
                    params: vec![ANFParam {
                        name: "x".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                    body: vec![],
                    is_public: false,
                },
                ANFMethod {
                    name: "check".to_string(),
                    params: vec![ANFParam {
                        name: "v".to_string(),
                        param_type: "bigint".to_string(),
                    }],
                    body: vec![
                        ANFBinding {
                            name: "t0".to_string(),
                            value: ANFValue::LoadParam { name: "v".to_string() },
                        },
                        ANFBinding {
                            name: "t1".to_string(),
                            value: ANFValue::LoadProp { name: "x".to_string() },
                        },
                        ANFBinding {
                            name: "t2".to_string(),
                            value: ANFValue::BinOp {
                                op: "===".to_string(),
                                left: "t0".to_string(),
                                right: "t1".to_string(),
                                result_type: None,
                            },
                        },
                        ANFBinding {
                            name: "t3".to_string(),
                            value: ANFValue::Assert { value: "t2".to_string() },
                        },
                    ],
                    is_public: true,
                },
            ],
        };

        let stack_methods = lower_to_stack(&program).expect("stack lowering should succeed");
        let result = emit(&stack_methods).expect("emit should succeed");

        // With a single public method, there should be no OP_IF method dispatch
        // (the dispatch table is only needed for 2+ public methods)
        assert!(
            !result.script_asm.contains("OP_IF"),
            "single public method should NOT produce OP_IF dispatch; got asm: {}",
            result.script_asm
        );
    }
}
