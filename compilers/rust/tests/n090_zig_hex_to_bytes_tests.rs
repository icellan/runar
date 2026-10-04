//! N-090: the Rust tier's `.runar.zig` parser left `runar.hexToBytes("<hex>")`
//! as an ordinary call, so a property initialised with it was refused
//! ("initializer must be a literal value") and the checked-in
//! examples/zig/tic-tac-toe/TicTacToe.runar.zig did not compile.
//!
//! Proves: `runar.hexToBytes("<hex>")` lowers to a ByteStringLiteral holding
//! the hex verbatim (as 01-parse-zig.ts, the Zig tier and Python do); a
//! non-literal argument is refused with TS's diagnostic; the Zig-surface
//! TicTacToe compiles to the same script as the TS-surface TicTacToe in this
//! tier.
//! Does NOT prove: identity with the TS compiler (pinned by the
//! hex-to-bytes-initializer conformance fixture and the remediation sweep),
//! or that the hex payload is well-formed (TS does not check it either).

use runar_compiler_rust::compile_from_source;
use runar_compiler_rust::frontend::ast::Expression;
use runar_compiler_rust::frontend::parser::parse_source;
use std::path::Path;

const SOURCE: &str = r#"const runar = @import("runar");

pub const H = struct {
    pub const Contract = runar.SmartContract;

    prefix: runar.Readonly(runar.ByteString) = runar.hexToBytes("1976a914"),
    x: runar.ByteString,

    pub fn init(x: runar.ByteString) H {
        return .{ .x = x };
    }

    pub fn verify(self: *const H, b: runar.ByteString) void {
        runar.assert(runar.bytesEq(runar.cat(self.prefix, self.x), b));
    }
};
"#;

#[test]
fn hex_to_bytes_initializer_is_a_bytestring_literal() {
    let result = parse_source(SOURCE, Some("H.runar.zig"));
    assert!(result.errors.is_empty(), "unexpected errors: {:?}", result.errors);
    let contract = result.contract.expect("contract");
    let prefix = contract
        .properties
        .iter()
        .find(|p| p.name == "prefix")
        .expect("property 'prefix'");
    match &prefix.initializer {
        Some(Expression::ByteStringLiteral { value }) => assert_eq!(value, "1976a914"),
        other => panic!("expected ByteStringLiteral initializer, got {:?}", other),
    }
}

#[test]
fn hex_to_bytes_non_literal_argument_is_refused() {
    let source = SOURCE.replace(r#"runar.hexToBytes("1976a914")"#, "runar.hexToBytes(x)");
    let result = parse_source(&source, Some("H.runar.zig"));
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.to_string().contains("runar.hexToBytes expects a string literal argument")),
        "expected TS's diagnostic, got {:?}",
        result.errors
    );
}

#[test]
fn tic_tac_toe_zig_example_compiles_like_the_ts_surface() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let zig = compile_from_source(&examples.join("zig/tic-tac-toe/TicTacToe.runar.zig"))
        .expect("TicTacToe.runar.zig must compile");
    let ts = compile_from_source(&examples.join("ts/tic-tac-toe/TicTacToe.runar.ts"))
        .expect("TicTacToe.runar.ts must compile");
    assert!(!zig.script.is_empty());
    assert_eq!(zig.script, ts.script, "Zig-surface TicTacToe differs from the TS surface");
}
