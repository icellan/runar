//! N-462 -- an arity error inside a `.runar.zig` method body is located at the
//! offending STATEMENT (`line:col` of its first token), as Go, Python, Ruby and
//! Java report it.
//!
//! Rust anchored it at `method.source_location`, and the Zig parser stamps a
//! method with the position AFTER its body (the next token), so the error was
//! reported at the following method (or the closing brace of the struct)
//! instead of at the call. The typechecker now tracks the current statement.
//!
//! Proves: for a private-helper call with the wrong number of arguments, the
//! Rust tier reports the statement's own position (the AST stores a
//! 1-based column; the CLI prints it 0-based, which is what the other tiers print).
//! Does not prove: expression-granular anchors (the Zig surface records no
//! expression positions) or any surface other than `.runar.zig`.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

const SOURCE: &str = r#"const runar = @import("runar");

pub const Arity = struct {
    pub const Contract = runar.StatefulSmartContract;

    counter: i64 = 0,

    pub fn init(counter: i64) Arity {
        return .{ .counter = counter };
    }

    fn record(self: *Arity, payload: runar.ByteString) void {
        _ = payload;
        self.counter = self.counter + 1;
    }

    fn fork(self: *Arity, amount: i64, leftover: i64) void {
        _ = amount;
        self.counter = leftover;
    }

    pub fn log(self: *Arity, payload: runar.ByteString) void {
        self.record(payload, payload);
        runar.assert(true);
    }

    pub fn partition(self: *Arity, amount: i64, leftover: i64) void {
        self.fork(amount, leftover, leftover);
        runar.assert(true);
    }
};
"#;

fn located(message_prefix: &str) -> (usize, usize) {
    let result = compile_from_source_str_with_result(
        SOURCE,
        Some("Arity.runar.zig"),
        &CompileOptions::default(),
    );
    let d = result
        .diagnostics
        .iter()
        .find(|d| d.severity == Severity::Error && d.message.starts_with(message_prefix))
        .unwrap_or_else(|| panic!("no '{message_prefix}' error in {:?}", result.diagnostics));
    let loc = d.loc.as_ref().expect("arity error carries a location");
    (loc.line, loc.column)
}

#[test]
fn zig_private_call_arity_error_points_at_the_call_statement() {
    // `self.record(payload, payload);` is line 23, `self` at AST column 9 (1-based; the CLI prints 8).
    assert_eq!(located("record() expects 1 argument(s), got 2"), (23, 9));
}

#[test]
fn zig_private_call_arity_error_in_last_method_points_at_the_call_statement() {
    // `self.fork(...)` is line 28; the struct's closing brace is line 32.
    assert_eq!(located("fork() expects 2 argument(s), got 3"), (28, 9));
}
