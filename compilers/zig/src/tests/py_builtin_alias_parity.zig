//! R-039 — irregular Python builtin aliases must map identically in all 7 tiers.
//!
//! Python contracts are written in snake_case and every tier's `.runar.py`
//! parser rewrites the identifiers to the canonical Rúnar camelCase names. Most
//! names fall out of a mechanical snake→camel rule, but five do not and
//! therefore need an explicit entry in each tier's special-name table:
//!
//!   int_to_str           -> int2str            (digit: "to" collapses to "2")
//!   safe_div             -> safediv            (no interior capital)
//!   safe_mod             -> safemod            (no interior capital)
//!   div_mod              -> divmod             (no interior capital)
//!   require_output_p2pkh -> requireOutputP2PKH (all-caps PKH token)
//!
//! Before this test the Zig tier had safe_div/safe_mod/div_mod but neither
//! int_to_str nor require_output_p2pkh: the mechanical rule produced
//! `intToStr` and `requireOutputP2pkh`, which the type checker rejects as
//! unknown functions, while the Python tier compiled the very same source.
//! CLAUDE.md makes frontend parity a no-exceptions invariant, so that is a
//! parity break.
//!
//! The pinned hexes are the SEVEN-TIER agreed fold-OFF output.

const std = @import("std");
const compiler_api = @import("../compiler_api.zig");

const INT2STR_SNAKE =
    \\from runar import SmartContract, Bigint, ByteString, public, assert_, int_to_str, len_
    \\
    \\
    \\class Encoder(SmartContract):
    \\    n: Bigint
    \\
    \\    def __init__(self, n: Bigint):
    \\        super().__init__(n)
    \\        self.n = n
    \\
    \\    @public
    \\    def unlock(self):
    \\        out: ByteString = int_to_str(self.n, 4)
    \\        assert_(len_(out) == 4)
;

const MATH_ALIASES =
    \\from runar import SmartContract, Bigint, public, assert_
    \\
    \\
    \\class Aliases(SmartContract):
    \\    n: Bigint
    \\
    \\    def __init__(self, n: Bigint):
    \\        super().__init__(n)
    \\        self.n = n
    \\
    \\    @public
    \\    def unlock(self):
    \\        a: Bigint = safe_div(self.n, 3)
    \\        b: Bigint = safe_mod(self.n, 3)
    \\        c: Bigint = div_mod(self.n, 3)
    \\        assert_(a + b + c > 0)
;

const INTENT_SNAKE =
    \\from runar import (
    \\    StatefulSmartContract, ByteString, Bigint, Readonly, public,
    \\)
    \\
    \\
    \\class Intent(StatefulSmartContract):
    \\    bondPKH: Readonly[ByteString]
    \\    bondAmount: Readonly[Bigint]
    \\    count: Bigint
    \\
    \\    def __init__(self, bondPKH: ByteString, bondAmount: Bigint, count: Bigint):
    \\        super().__init__(bondPKH, bondAmount, count)
    \\        self.bondPKH = bondPKH
    \\        self.bondAmount = bondAmount
    \\        self.count = count
    \\
    \\    @public
    \\    def payBond(self):
    \\        require_output_p2pkh(0, self.bondPKH, self.bondAmount)
;

const INTENT_CAMEL =
    \\from runar import (
    \\    StatefulSmartContract, ByteString, Bigint, Readonly, public,
    \\)
    \\
    \\
    \\class Intent(StatefulSmartContract):
    \\    bondPKH: Readonly[ByteString]
    \\    bondAmount: Readonly[Bigint]
    \\    count: Bigint
    \\
    \\    def __init__(self, bondPKH: ByteString, bondAmount: Bigint, count: Bigint):
    \\        super().__init__(bondPKH, bondAmount, count)
    \\        self.bondPKH = bondPKH
    \\        self.bondAmount = bondAmount
    \\        self.count = count
    \\
    \\    @public
    \\    def payBond(self):
    \\        requireOutputP2PKH(0, self.bondPKH, self.bondAmount)
;

const UNKNOWN_BUILTIN =
    \\from runar import SmartContract, Bigint, public, assert_
    \\
    \\
    \\class Unknown(SmartContract):
    \\    n: Bigint
    \\
    \\    def __init__(self, n: Bigint):
    \\        super().__init__(n)
    \\        self.n = n
    \\
    \\    @public
    \\    def unlock(self):
    \\        assert_(not_a_builtin(self.n) > 0)
;

/// Fold-OFF compile of a `.runar.py` source to Bitcoin Script hex. Caller owns
/// the returned slice.
fn compileScriptHex(
    allocator: std.mem.Allocator,
    source: []const u8,
    file_name: []const u8,
) ![]const u8 {
    const result = try compiler_api.compileSourceWithOptions(allocator, source, file_name, true);
    if (result.artifact_json) |json| allocator.free(json);
    return result.script_hex;
}

test "int_to_str lowers to the seven-tier int2str script" {
    const allocator = std.testing.allocator;
    const hex = try compileScriptHex(allocator, INT2STR_SNAKE, "Encoder.runar.py");
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("0054808277549c", hex);
}

test "safe_div / safe_mod / div_mod lower to the seven-tier script" {
    const allocator = std.testing.allocator;
    const hex = try compileScriptHex(allocator, MATH_ALIASES, "Aliases.runar.py");
    defer allocator.free(hex);
    try std.testing.expectEqualStrings(
        "00537692699600537692699700536e967b7b97757b7b937c9300a0",
        hex,
    );
}

test "require_output_p2pkh is byte-identical to requireOutputP2PKH" {
    const allocator = std.testing.allocator;
    const snake = try compileScriptHex(allocator, INTENT_SNAKE, "Intent.runar.py");
    defer allocator.free(snake);
    const camel = try compileScriptHex(allocator, INTENT_CAMEL, "Intent.runar.py");
    defer allocator.free(camel);
    try std.testing.expectEqualStrings(camel, snake);
}

test "an unknown snake_case function is still rejected" {
    // Guards against the lazy fix: a blanket pass-through that maps any
    // snake_case identifier onto a builtin name would let this compile.
    const allocator = std.testing.allocator;
    const result = compileScriptHex(allocator, UNKNOWN_BUILTIN, "Unknown.runar.py");
    try std.testing.expectError(error.TypeCheckFailed, result);
}
