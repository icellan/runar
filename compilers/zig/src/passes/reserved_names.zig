//! N-065 / N-060 — compiler-reserved names. Port of
//! packages/runar-compiler/src/passes/reserved-names.ts (see there for the
//! full inventory of which pass mints which family, and what is NOT reserved
//! and why).
//!
//! Several passes mint names into the same namespace user identifiers live in,
//! and every later pass resolves a name by string equality, so a user name
//! spelled like a minted one aliases two different values. A program that
//! declares one is refused with ONE sentence shared verbatim by all seven
//! tiers (`message`).
//!
//!   ANF temps               t<digits>, __merge$<digits>
//!   FixedArray expansion    <name>__<digits>, __idx_<digits>, __val_<digits>
//!   stack lowering          _codePart, __param_*, __shadowed_*, _pub_<digits>
//!   auto-injected params    _changePKH, _changeAmount, _newAmount,
//!                           _serialisedOutputs, _prevOutScript_<digits>,
//!                           and txPreimage in a StatefulSmartContract

const std = @import("std");

/// The shared diagnostic. Caller owns the returned slice.
pub fn message(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "'{s}' is reserved for compiler-generated names and cannot be used as an identifier", .{name});
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < '0' or c > '9') return false;
    return true;
}

/// `prefix` followed by one or more ASCII digits.
fn prefixDigits(name: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, name, prefix) and allDigits(name[prefix.len..]);
}

fn isStackLoweringReserved(name: []const u8) bool {
    return std.mem.eql(u8, name, "_codePart") or
        std.mem.startsWith(u8, name, "__param_") or
        std.mem.startsWith(u8, name, "__shadowed_") or
        prefixDigits(name, "_pub_");
}

fn isAnfBindingReserved(name: []const u8) bool {
    return prefixDigits(name, "t") or prefixDigits(name, "__merge$");
}

/// `^.+__[0-9]+$`: a non-empty stem, `__`, then digits to the end.
fn isArraySlotName(name: []const u8) bool {
    var i: usize = name.len;
    while (i > 0 and name[i - 1] >= '0' and name[i - 1] <= '9') i -= 1;
    if (i == name.len) return false; // no trailing digits
    // Any `__` whose remainder is all digits, with a non-empty stem before it.
    // With the digit run ending at `name.len`, the separator must sit right
    // before some suffix of that run; the greedy regex backtracks to any such
    // split, so check every position in the digit run.
    var j: usize = i;
    while (j < name.len) : (j += 1) {
        if (j >= 3 and name[j - 1] == '_' and name[j - 2] == '_') return true;
    }
    return false;
}

fn isSourceOnlyReserved(name: []const u8) bool {
    return isArraySlotName(name) or
        prefixDigits(name, "__idx_") or
        prefixDigits(name, "__val_") or
        std.mem.eql(u8, name, "_changePKH") or
        std.mem.eql(u8, name, "_changeAmount") or
        std.mem.eql(u8, name, "_newAmount") or
        std.mem.eql(u8, name, "_serialisedOutputs") or
        prefixDigits(name, "_prevOutScript_");
}

/// True if a SOURCE program may not declare `name` (after name mapping).
pub fn isReservedSourceName(name: []const u8, stateful: bool) bool {
    return isStackLoweringReserved(name) or
        isAnfBindingReserved(name) or
        isSourceOnlyReserved(name) or
        (stateful and std.mem.eql(u8, name, "txPreimage"));
}

/// `--ir` rule: every position refuses stack lowering's slot names; a
/// declaration (property, method, parameter, loop variable, or the name a
/// load_param / load_prop / update_prop addresses) also refuses the ANF
/// binding families.
pub fn isReservedIrName(name: []const u8, declaration: bool) bool {
    return isStackLoweringReserved(name) or (declaration and isAnfBindingReserved(name));
}

test "reserved-name families" {
    const t = std.testing;
    try t.expect(isReservedSourceName("t0", false));
    try t.expect(isReservedSourceName("t12", false));
    try t.expect(!isReservedSourceName("t", false));
    try t.expect(!isReservedSourceName("t1x", false));
    try t.expect(isReservedSourceName("x__0", false));
    try t.expect(isReservedSourceName("Grid__0__1", false));
    try t.expect(!isReservedSourceName("__0", false));
    try t.expect(!isReservedSourceName("a_0", false));
    try t.expect(isReservedSourceName("__merge$0", false));
    try t.expect(isReservedSourceName("__idx_3", false));
    try t.expect(!isReservedSourceName("__while_no_init", false));
    try t.expect(isReservedSourceName("txPreimage", true));
    try t.expect(!isReservedSourceName("txPreimage", false));
    try t.expect(isReservedSourceName("_pub_0", false));
    try t.expect(isReservedIrName("_codePart", false));
    try t.expect(!isReservedIrName("t3", false));
    try t.expect(isReservedIrName("t3", true));
    try t.expect(!isReservedIrName("txPreimage", true));
}
