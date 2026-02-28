//! Pass 6: Emit -- converts Stack IR to Bitcoin Script bytes (hex string).
//!
//! Walks the StackOp list and encodes each operation as one or more Bitcoin
//! Script opcodes, producing both a hex-encoded script and a human-readable
//! ASM representation.

use super::opcodes::opcode_byte;
use super::stack::{PushValue, StackMethod, StackOp};

// ---------------------------------------------------------------------------
// EmitResult
// ---------------------------------------------------------------------------

/// The output of the emission pass.
#[derive(Debug, Clone)]
pub struct EmitResult {
    pub script_hex: String,
    pub script_asm: String,
}

// ---------------------------------------------------------------------------
// Emit context
// ---------------------------------------------------------------------------

struct EmitContext {
    hex_parts: Vec<String>,
    asm_parts: Vec<String>,
}

impl EmitContext {
    fn new() -> Self {
        EmitContext {
            hex_parts: Vec::new(),
            asm_parts: Vec::new(),
        }
    }

    fn emit_opcode(&mut self, name: &str) -> Result<(), String> {
        let byte = opcode_byte(name)
            .ok_or_else(|| format!("unknown opcode: {}", name))?;
        self.hex_parts.push(format!("{:02x}", byte));
        self.asm_parts.push(name.to_string());
        Ok(())
    }

    fn emit_push(&mut self, value: &PushValue) {
        let (h, a) = encode_push_value(value);
        self.hex_parts.push(h);
        self.asm_parts.push(a);
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

/// Encode an i64 as a Bitcoin Script number (little-endian, sign-magnitude).
pub fn encode_script_number(n: i64) -> Vec<u8> {
    if n == 0 {
        return Vec::new();
    }

    let negative = n < 0;
    let mut abs = if negative { -(n as i128) } else { n as i128 } as u64;

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
pub fn encode_push_int(n: i64) -> (String, String) {
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
// Public API
// ---------------------------------------------------------------------------

/// Emit a slice of StackMethods as Bitcoin Script hex and ASM.
///
/// For contracts with multiple public methods, generates a method dispatch
/// preamble using OP_IF/OP_ELSE chains.
pub fn emit(methods: &[StackMethod]) -> Result<EmitResult, String> {
    let mut ctx = EmitContext::new();

    // Filter to public methods (exclude constructor)
    let public_methods: Vec<&StackMethod> = methods
        .iter()
        .filter(|m| m.name != "constructor")
        .collect();

    if public_methods.is_empty() {
        return Ok(EmitResult {
            script_hex: String::new(),
            script_asm: String::new(),
        });
    }

    if public_methods.len() == 1 {
        for op in &public_methods[0].ops {
            emit_stack_op(op, &mut ctx)?;
        }
    } else {
        emit_method_dispatch(&public_methods, &mut ctx)?;
    }

    Ok(EmitResult {
        script_hex: ctx.get_hex(),
        script_asm: ctx.get_asm(),
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
            ctx.emit_push(&PushValue::Int(i as i64));
            ctx.emit_opcode("OP_NUMEQUAL")?;
            ctx.emit_opcode("OP_IF")?;
            ctx.emit_opcode("OP_DROP")?;
        } else {
            ctx.emit_opcode("OP_DROP")?;
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
    })
}
