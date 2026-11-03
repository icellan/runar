//! Pre-existing defect found while porting F-213: the `.runar.java` parser
//! read every `(identifier)` as a cast `(Type) operand`.
//!
//! parsePrimary's `(` arm asked `looksLikeCast` whether an identifier (with
//! optional `.x` / `<..>` / `[]` suffixes) was followed by `)`, and if so
//! skipped it as a type and parsed the NEXT unary expression as the operand.
//! So `(((value)))` and `-(-(value))` were refused with `unexpected token:
//! ')'`, and `(value) - limit` compiled as `-limit` — the left operand
//! silently dropped. The TS reference and the Go tier parse `(` as a
//! parenthesised expression only (Rúnar Java has no casts), and so do the
//! other six tiers.
//!
//! What this proves: on this tier's .runar.java surface a parenthesised
//! identifier is an expression — the three shapes above compile, to the same
//! script as their unparenthesised spelling. What it does NOT prove: anything
//! about the other surfaces, or cross-tier byte parity (conformance does).

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const HEAD =
    \\package p;
    \\
    \\import runar.lang.SmartContract;
    \\import runar.lang.annotations.Public;
    \\import runar.lang.annotations.Readonly;
    \\import runar.lang.types.Bigint;
    \\
    \\import static runar.lang.Builtins.assertThat;
    \\
    \\class P extends SmartContract {
    \\    @Readonly Bigint limit;
    \\    P(Bigint limit) { super(limit); this.limit = limit; }
    \\    @Public
    \\    void check(Bigint value, Bigint other) {
    \\        Bigint result = Bigint.ZERO;
    \\
;
const TAIL =
    \\
    \\        assertThat(result.gt(Bigint.ZERO));
    \\    }
    \\}
    \\
;

fn expectSameScript(paren: []const u8, plain: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const src_p = try std.mem.concat(a, u8, &.{ HEAD, "        result = ", paren, ";", TAIL });
    const src_q = try std.mem.concat(a, u8, &.{ HEAD, "        result = ", plain, ";", TAIL });
    const hp = compiler_api.compileSourceToHex(a, src_p, "P.runar.java") catch |err| {
        std.debug.print("`{s}` refused: {s}\n", .{ paren, @errorName(err) });
        return err;
    };
    const hq = try compiler_api.compileSourceToHex(a, src_q, "P.runar.java");
    try std.testing.expectEqualStrings(hq, hp);
}

test "java: a parenthesised identifier is an expression, not a cast" {
    try expectSameScript("(((value)))", "value");
    try expectSameScript("-(-(value))", "-(-value)");
}

test "java: `(value) - other` keeps its left operand" {
    try expectSameScript("(value) - other", "value - other");
}
