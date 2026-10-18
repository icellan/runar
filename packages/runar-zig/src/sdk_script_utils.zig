const std = @import("std");
const types = @import("sdk_types.zig");
const state_mod = @import("sdk_state.zig");

// ---------------------------------------------------------------------------
// Script utilities — constructor arg extraction and artifact matching
// ---------------------------------------------------------------------------

/// Result of reading a script element at a given hex offset.
const ScriptElement = struct {
    data_hex: []const u8, // slice into the input hex (not owned)
    total_hex_chars: usize,
    opcode: u8,
};

/// Read a single Bitcoin Script element (opcode + data) at the given hex
/// offset, or `error.MalformedScript` (F-238) if the opcode byte itself, an
/// OP_PUSHDATA1/2/4 length prefix, or the declared push payload runs past
/// the end of `hex` (or is not valid hex). A provider-supplied script is
/// untrusted input; a truncated push must never come back as a short,
/// silently-wrong `data_hex` — it would also desynchronise every later
/// slot's offset in the caller's walk.
fn readScriptElement(hex: []const u8, offset: usize) error{MalformedScript}!ScriptElement {
    if (offset + 2 > hex.len) return error.MalformedScript;

    const opcode = hexByteAt(hex, offset) orelse return error.MalformedScript;

    if (opcode == 0x00) return .{ .data_hex = "", .total_hex_chars = 2, .opcode = opcode };

    if (opcode >= 0x01 and opcode <= 0x4b) {
        const data_len = @as(usize, opcode) * 2;
        const start = offset + 2;
        if (start + data_len > hex.len) return error.MalformedScript;
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 2 + data_len, .opcode = opcode };
    }

    if (opcode == 0x4c) {
        // OP_PUSHDATA1
        if (offset + 4 > hex.len) return error.MalformedScript;
        const len = hexByteAt(hex, offset + 2) orelse return error.MalformedScript;
        const data_len = @as(usize, len) * 2;
        const start = offset + 4;
        if (start + data_len > hex.len) return error.MalformedScript;
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 4 + data_len, .opcode = opcode };
    }

    if (opcode == 0x4d) {
        // OP_PUSHDATA2
        if (offset + 6 > hex.len) return error.MalformedScript;
        const lo = hexByteAt(hex, offset + 2) orelse return error.MalformedScript;
        const hi = hexByteAt(hex, offset + 4) orelse return error.MalformedScript;
        const len = @as(usize, lo) | (@as(usize, hi) << 8);
        const data_len = len * 2;
        const start = offset + 6;
        if (start + data_len > hex.len) return error.MalformedScript;
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 6 + data_len, .opcode = opcode };
    }

    if (opcode == 0x4e) {
        // OP_PUSHDATA4
        if (offset + 10 > hex.len) return error.MalformedScript;
        const b0 = hexByteAt(hex, offset + 2) orelse return error.MalformedScript;
        const b1 = hexByteAt(hex, offset + 4) orelse return error.MalformedScript;
        const b2 = hexByteAt(hex, offset + 6) orelse return error.MalformedScript;
        const b3 = hexByteAt(hex, offset + 8) orelse return error.MalformedScript;
        const len = @as(usize, b0) | (@as(usize, b1) << 8) | (@as(usize, b2) << 16) | (@as(usize, b3) << 24);
        const data_len = len * 2;
        const start = offset + 10;
        if (start + data_len > hex.len) return error.MalformedScript;
        return .{ .data_hex = hex[start .. start + data_len], .total_hex_chars = 10 + data_len, .opcode = opcode };
    }

    return .{ .data_hex = "", .total_hex_chars = 2, .opcode = opcode };
}

/// Decode a Script number from hex data (sign-magnitude LE).
///
/// N-074: a Script number is ARBITRARY PRECISION — Rúnar contracts routinely
/// carry 256-bit EC scalars and 1024-bit+ Rabin moduli as plain `bigint`
/// constructor args. This used to stage the bytes through a fixed `[8]u8`
/// buffer and accumulate into an `i64`, so anything wider than 8 data bytes
/// (`|v| >= 2^63`) indexed past the end of that buffer and PANICKED instead of
/// decoding. The encode side (`sdk_state.encodeBigScriptNumber`) was already
/// arbitrary-precision; the asymmetry was the bug.
///
/// Returns `.int` whenever the value fits an i64 — the overwhelmingly common
/// case, and the variant every existing caller switches on — and the `.big_int`
/// decimal string (owned by the caller, matching the convention `parseInitialValue`
/// in `sdk_contract.zig` already uses) only when it genuinely cannot.
fn decodeScriptNumberValue(allocator: std.mem.Allocator, data_hex: []const u8) !types.StateValue {
    if (data_hex.len == 0) return .{ .int = 0 };
    const byte_count = data_hex.len / 2;

    var bytes = try allocator.alloc(u8, byte_count);
    defer allocator.free(bytes);
    for (0..byte_count) |i| {
        bytes[i] = hexByteAt(data_hex, i * 2) orelse 0;
    }
    const negative = (bytes[byte_count - 1] & 0x80) != 0;
    bytes[byte_count - 1] &= 0x7f;

    // Fast path: after the sign bit is masked off, 8 magnitude bytes can hold
    // at most 2^63-1, so this cannot overflow. Byte-identical to the old
    // behaviour for every value that ever decoded correctly.
    if (byte_count <= 8) {
        var result: i64 = 0;
        var i: usize = byte_count;
        while (i > 0) {
            i -= 1;
            result = (result << 8) | @as(i64, bytes[i]);
        }
        return .{ .int = if (negative) -result else result };
    }

    const decimal = try magnitudeToDecimal(allocator, bytes, negative);
    // A non-minimal encoding can be >8 bytes and still fit; keep `.int` then so
    // the variant a value comes back as depends on the VALUE, not its padding.
    if (std.fmt.parseInt(i64, decimal, 10)) |n| {
        allocator.free(decimal);
        return .{ .int = n };
    } else |_| {}
    return .{ .big_int = decimal };
}

/// Render a little-endian magnitude as a signed decimal string (caller owns it).
///
/// Repeated multiply-by-256-and-add over base-10 digits — the mirror of the
/// repeated divide-by-256 that `sdk_state.encodeBigScriptNumber` uses to go the
/// other way, and likewise needs no bignum dependency.
fn magnitudeToDecimal(allocator: std.mem.Allocator, le_bytes: []const u8, negative: bool) ![]u8 {
    var digits: std.ArrayListUnmanaged(u8) = .empty; // base-10, least significant first
    defer digits.deinit(allocator);
    try digits.append(allocator, 0);

    var i: usize = le_bytes.len;
    while (i > 0) {
        i -= 1;
        var carry: u32 = le_bytes[i];
        for (digits.items) |*d| {
            const v: u32 = @as(u32, d.*) * 256 + carry;
            d.* = @intCast(v % 10);
            carry = v / 10;
        }
        while (carry > 0) {
            try digits.append(allocator, @intCast(carry % 10));
            carry /= 10;
        }
    }

    // Trim leading zeros (keeping a single "0" for a zero magnitude).
    var len = digits.items.len;
    while (len > 1 and digits.items[len - 1] == 0) len -= 1;
    const is_zero = len == 1 and digits.items[0] == 0;

    const sign_len: usize = if (negative and !is_zero) 1 else 0;
    var out = try allocator.alloc(u8, sign_len + len);
    if (sign_len == 1) out[0] = '-';
    for (0..len) |k| {
        out[sign_len + k] = '0' + digits.items[len - 1 - k];
    }
    return out;
}

/// Interpret a script element as a typed value.
/// How a constructor-slot value of a given ABI type is encoded in the script.
const AbiValueEncoding = enum { scriptnum, bool_, data };

/// TABLE, not a hand-maintained `eql` chain: the two spellings missing from
/// the old chain — the `bigint` aliases `RabinSig` / `RabinPubKey`, and the
/// CANONICAL `boolean` (only the `bool` alias was compared) — each silently
/// turned a value into a hex string on the way back off chain. Mirrors
/// `packages/runar-ir-schema/src/abi-type-encoding.ts`, the same table the
/// compiler stamps `ConstructorSlot.valueEncoding` from.
const ABI_VALUE_ENCODINGS = [_]struct { name: []const u8, encoding: AbiValueEncoding }{
    .{ .name = "bigint", .encoding = .scriptnum },
    .{ .name = "int", .encoding = .scriptnum },
    // RabinSig / RabinPubKey are bigint aliases; `verifyRabinSig` lowers to
    // OP_MOD, which reads its operand as a little-endian sign-magnitude Script
    // number — exactly what `bigint` gets.
    .{ .name = "RabinSig", .encoding = .scriptnum },
    .{ .name = "RabinPubKey", .encoding = .scriptnum },
    // `boolean` is canonical; `bool` is the alias several frontends spell.
    .{ .name = "boolean", .encoding = .bool_ },
    .{ .name = "bool", .encoding = .bool_ },
};

/// Classify an ABI type name. ByteString and every fixed-width byte type fall
/// through to `.data` (a raw push).
fn abiValueEncoding(type_name: []const u8) AbiValueEncoding {
    for (ABI_VALUE_ENCODINGS) |entry| {
        if (std.mem.eql(u8, type_name, entry.name)) return entry.encoding;
    }
    return .data;
}

fn interpretScriptElement(allocator: std.mem.Allocator, opcode: u8, data_hex: []const u8, type_name: []const u8) !types.StateValue {
    const encoding = abiValueEncoding(type_name);

    if (encoding == .scriptnum) {
        if (opcode == 0x00) return .{ .int = 0 };
        if (opcode >= 0x51 and opcode <= 0x60) return .{ .int = @as(i64, opcode) - 0x50 };
        if (opcode == 0x4f) return .{ .int = -1 };
        return decodeScriptNumberValue(allocator, data_hex);
    }

    if (encoding == .bool_) {
        if (opcode == 0x00) return .{ .boolean = false };
        if (opcode == 0x51) return .{ .boolean = true };
        return .{ .boolean = !std.mem.eql(u8, data_hex, "00") };
    }

    // Default: bytes.
    //
    // S1: a ByteString (or other non-numeric) ctor arg whose 1-byte value was
    // MINIMALDATA-encoded as OP_1..OP_16 / OP_1NEGATE carries no separate data
    // bytes in the script — `readScriptElement` reports an empty `data_hex` for
    // these opcodes (they aren't direct pushes or OP_PUSHDATA*). The opcode
    // itself IS the value; reconstruct it instead of forwarding the (empty)
    // data_hex. OP_0 correctly falls through to `data_hex` (the empty string),
    // matching OP_0's true semantics (pushes [], not a 1-byte 0x00).
    if (opcode >= 0x51 and opcode <= 0x60) {
        var buf: [2]u8 = undefined;
        _ = std.fmt.bufPrint(&buf, "{x:0>2}", .{opcode - 0x50}) catch unreachable;
        return .{ .bytes = try allocator.dupe(u8, &buf) };
    }
    if (opcode == 0x4f) return .{ .bytes = try allocator.dupe(u8, "81") };

    return .{ .bytes = try allocator.dupe(u8, data_hex) };
}

/// Extract constructor argument values from a compiled on-chain script.
///
/// Uses `artifact.constructorSlots` to locate each constructor arg at its
/// byte offset, reads the push data, and deserializes according to the
/// ABI param type.
///
/// Returns a map from parameter name to StateValue. Caller owns the map and
/// all values within.
pub fn extractConstructorArgs(
    artifact: *const types.RunarArtifact,
    script_hex: []const u8,
    allocator: std.mem.Allocator,
) !std.StringHashMap(types.StateValue) {
    var result = std.StringHashMap(types.StateValue).init(allocator);
    errdefer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    if (artifact.constructor_slots.len == 0) return result;

    // Strip state suffix for stateful contracts
    var code_hex = script_hex;
    if (artifact.state_fields.len > 0) {
        const op_return_pos = state_mod.findLastOpReturn(script_hex);
        if (op_return_pos) |pos| {
            code_hex = script_hex[0..pos];
        }
    }

    // Walk EVERY slot in byte order. A constructor param referenced more than
    // once in the contract body emits one slot per reference, and each
    // occurrence's encoded width contributes to the cumulative offset shift —
    // deduplicating before the walk drops those widths and mis-aligns every
    // later slot on artifacts with repeated references. The VALUE is taken
    // from the first occurrence per param.
    var indices = try allocator.alloc(usize, artifact.constructor_slots.len);
    defer allocator.free(indices);
    for (0..artifact.constructor_slots.len) |i| indices[i] = i;

    const cs = artifact.constructor_slots;
    std.mem.sort(usize, indices, cs, struct {
        fn lessThan(ctx: []const types.ConstructorSlot, a: usize, b: usize) bool {
            return ctx[a].byte_offset < ctx[b].byte_offset;
        }
    }.lessThan);

    var assigned = std.AutoHashMap(i32, void).init(allocator);
    defer assigned.deinit();

    var cumulative_shift: i64 = 0;

    for (indices) |idx| {
        const slot = cs[idx];
        const adjusted_hex_offset: usize = @intCast((@as(i64, slot.byte_offset) + cumulative_shift) * 2);
        // F-238: a slot offset at or past the end of the script is itself a
        // malformed/mismatched provider script (every push needs at least an
        // opcode byte) — readScriptElement already rejects it; it used to be
        // silently skipped here instead, dropping the param from the result
        // with no error.
        const elem = try readScriptElement(code_hex, adjusted_hex_offset);
        // Template placeholders are exactly 1 byte, so the shift contributed by
        // each occurrence is its encoded width minus that byte. This must
        // accumulate for EVERY occurrence, including the ones whose value we
        // already captured.
        cumulative_shift += @divTrunc(@as(i64, @intCast(elem.total_hex_chars)), 2) - 1;

        if (assigned.contains(slot.param_index)) continue;

        const param_idx: usize = @intCast(slot.param_index);
        if (param_idx >= artifact.abi.constructor.params.len) continue;
        try assigned.put(slot.param_index, {});

        const param = artifact.abi.constructor.params[param_idx];
        const value = try interpretScriptElement(allocator, elem.opcode, elem.data_hex, param.type_name);
        const key = try allocator.dupe(u8, param.name);
        try result.put(key, value);
    }

    return result;
}

/// True when `s` is an even-length string of ASCII hex digits (N-317).
pub fn isHexBytes(s: []const u8) bool {
    if (s.len % 2 != 0) return false;
    for (s) |ch| {
        if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

/// Determine whether a given on-chain script was produced from the given
/// contract artifact (regardless of what constructor args were used).
///
/// Returns `error.MalformedScript` (F-238) if `script_hex` is not a
/// well-formed sequence of push elements at the offsets the artifact expects.
pub fn matchesArtifact(
    artifact: *const types.RunarArtifact,
    script_hex: []const u8,
) error{MalformedScript}!bool {
    // N-317: refuse anything that is not whole bytes of hex up front, so no
    // reader below sees a partial byte and every tier makes the same call.
    if (!isHexBytes(script_hex)) return error.MalformedScript;
    // Strip state suffix for stateful contracts
    var code_hex = script_hex;
    if (artifact.state_fields.len > 0) {
        const op_return_pos = state_mod.findLastOpReturn(script_hex);
        if (op_return_pos) |pos| {
            code_hex = script_hex[0..pos];
        }
    }

    const template = artifact.script;

    // N-316: compare literally only when the template has no slot of ANY kind.
    if (artifact.constructor_slots.len == 0 and artifact.code_sep_index_slots.len == 0 and
        artifact.code_part_len_slots.len == 0)
    {
        return std.mem.eql(u8, code_hex, template);
    }

    // Build sorted, deduplicated slots by byte offset
    // Use a simple inline sort since we can't allocate in a bool-returning fn
    var sorted_offsets: [64]struct { byte_offset: i32 } = undefined;
    var sorted_count: usize = 0;

    // Collect unique byte offsets. Every OP_0 placeholder the SDK replaces at
    // deploy time is one variable script element: constructor slots AND
    // codeSepIndex slots (the latter bake as OP_1 post-R-010, so comparing
    // them literally rejected every honest deployment of a stateful contract
    // that carries one; matches the TS/Go/Rust/Python tiers).
    const total_slots = artifact.constructor_slots.len + artifact.code_sep_index_slots.len;
    for (0..total_slots) |n| {
        const off = if (n < artifact.constructor_slots.len)
            artifact.constructor_slots[n].byte_offset
        else
            artifact.code_sep_index_slots[n - artifact.constructor_slots.len].byte_offset;
        var found = false;
        for (0..sorted_count) |k| {
            if (sorted_offsets[k].byte_offset == off) {
                found = true;
                break;
            }
        }
        if (!found) {
            if (sorted_count >= 64) return false;
            sorted_offsets[sorted_count] = .{ .byte_offset = off };
            sorted_count += 1;
        }
    }

    // Insertion sort
    // N-316: sorted_count is 0 when only codePartLenSlots exist; 1..0 would panic.
    for (1..@max(sorted_count, 1)) |i| {
        const key = sorted_offsets[i];
        var j: usize = i;
        while (j > 0 and sorted_offsets[j - 1].byte_offset > key.byte_offset) {
            sorted_offsets[j] = sorted_offsets[j - 1];
            j -= 1;
        }
        sorted_offsets[j] = key;
    }

    // N-051: a `codePartLenSlots` field holds the DEPLOYED code-part length,
    // not the template's placeholder value. It must equal the length of the
    // code part being matched (everything before the state section,
    // inscription envelope included).
    const code_len = code_hex.len / 2;
    if (code_len > 0xffffffff) return false;
    const code_len_u32: u32 = @intCast(code_len);
    var deployed_len: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&deployed_len, "{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        @as(u8, @truncate(code_len_u32)),       @as(u8, @truncate(code_len_u32 >> 8)),
        @as(u8, @truncate(code_len_u32 >> 16)), @as(u8, @truncate(code_len_u32 >> 24)),
    }) catch unreachable;

    var template_pos: usize = 0;
    var code_pos: usize = 0;

    for (0..sorted_count) |i| {
        const slot_hex_offset: usize = @intCast(sorted_offsets[i].byte_offset * 2);

        // Compare template segment before this slot
        if (slot_hex_offset < template_pos) return false;
        const template_segment_len = slot_hex_offset - template_pos;
        if (code_pos + template_segment_len > code_hex.len) return false;
        if (template_pos + template_segment_len > template.len) return false;

        if (!segmentMatches(artifact, template, template_pos, slot_hex_offset, code_hex, code_pos, &deployed_len)) return false;

        // Skip the placeholder in template (1 byte = 2 hex chars: OP_0)
        template_pos = slot_hex_offset + 2;

        // Read the actual element in the code script
        const elem_offset = code_pos + template_segment_len;
        const elem = try readScriptElement(code_hex, elem_offset);
        code_pos = elem_offset + elem.total_hex_chars;
    }

    // Compare the remaining suffix
    if (template_pos > template.len or code_pos > code_hex.len) return false;
    if (code_hex.len - code_pos != template.len - template_pos) return false;
    return segmentMatches(artifact, template, template_pos, template.len, code_hex, code_pos, &deployed_len);
}

/// Compare template[t_start..t_end] against code_hex starting at c_start
/// (same length), except that each N-051 `codePartLenSlots` field must hold
/// `deployed_len` (LE32 hex of the candidate's code-part length) instead of
/// the template's placeholder bytes. Caller guarantees the code range exists.
fn segmentMatches(
    artifact: *const types.RunarArtifact,
    template: []const u8,
    t_start: usize,
    t_end: usize,
    code_hex: []const u8,
    c_start: usize,
    deployed_len: *const [8]u8,
) bool {
    var t = t_start;
    var c = c_start;
    while (t < t_end) {
        var is_len_field = false;
        for (artifact.code_part_len_slots) |slot| {
            if (slot.byte_offset >= 0 and @as(usize, @intCast(slot.byte_offset)) * 2 == t) {
                is_len_field = true;
                break;
            }
        }
        if (is_len_field) {
            if (c + 8 > code_hex.len) return false;
            if (!std.mem.eql(u8, code_hex[c .. c + 8], deployed_len)) return false;
            t += 8;
            c += 8;
            continue;
        }
        if (template[t] != code_hex[c]) return false;
        t += 1;
        c += 1;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

fn hexByteAt(hex: []const u8, pos: usize) ?u8 {
    if (pos + 2 > hex.len) return null;
    const high = hexNibble(hex[pos]) orelse return null;
    const low = hexNibble(hex[pos + 1]) orelse return null;
    return (@as(u8, high) << 4) | @as(u8, low);
}

fn hexNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "extractConstructorArgs returns empty for no slots" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"5100","asm":"OP_1 OP_0",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    var result = try extractConstructorArgs(&artifact, "5100", allocator);
    defer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    try std.testing.expectEqual(@as(usize, 0), result.count());
}

test "matchesArtifact matches identical script" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"5100","asm":"OP_1 OP_0",
        \\"abi":{"constructor":{"params":[]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    try std.testing.expect(try matchesArtifact(&artifact, "5100"));
    try std.testing.expect(!try matchesArtifact(&artifact, "5200"));
}

test "matchesArtifact with constructor slots" {
    const allocator = std.testing.allocator;
    // Template has OP_0 (00) at byte 0 as a placeholder
    const json =
        \\{"contractName":"P2PKH","version":"1","compilerVersion":"1.0","script":"0088ac","asm":"OP_0 OP_EQUALVERIFY OP_CHECKSIG",
        \\"abi":{"constructor":{"params":[{"name":"pkh","type":"Addr"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[{"paramIndex":0,"byteOffset":0}],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    // On-chain script with a 20-byte push at offset 0: 14 + 20 bytes + "88ac"
    // OP_PUSH20 (0x14) + 20 zero bytes + OP_EQUALVERIFY + OP_CHECKSIG
    const on_chain = "14" ++ "00" ** 20 ++ "88ac";
    try std.testing.expect(try matchesArtifact(&artifact, on_chain));

    // Different suffix should not match
    const bad = "14" ++ "00" ** 20 ++ "88ad";
    try std.testing.expect(!try matchesArtifact(&artifact, bad));
}

// ---------------------------------------------------------------------------
// F-238 — readScriptElement must refuse malformed provider-supplied scripts
// instead of silently truncating.
//
// Before this fix, a push whose declared length (a direct push opcode
// 0x01-0x4b, or an OP_PUSHDATA1/2/4 length prefix) ran past the remaining
// bytes returned an EMPTY data_hex with a total_hex_chars that did not
// account for the missing payload, instead of erroring — extractConstructorArgs
// / matchesArtifact then treat that as a valid (wrong) element, corrupting
// every later slot's offset in the same walk.
//
// PROVES: extractConstructorArgs / matchesArtifact return error.MalformedScript
// for every vector in the brief's testable assertion, and a valid push of
// every pushdata flavour still decodes unchanged.
// DOES NOT PROVE: fail-closed behaviour of any other script reader in this
// package.
// ---------------------------------------------------------------------------

const f238_malformed_vectors = [_][]const u8{
    "", // no opcode byte at all
    "f", // odd-length hex, can't even form an opcode byte
    "05aabb", // direct push declares 5 bytes, only 2 remain
    "4c", // OP_PUSHDATA1 with no length byte
    "4c05aa", // OP_PUSHDATA1 declares 5 bytes, only 1 remains
    "4d0100", // OP_PUSHDATA2 length prefix present, 0 of the 1 declared bytes remain
    "4e01000000", // OP_PUSHDATA4 length prefix present, 0 of the 1 declared bytes remain
};

fn f238OneSlotArtifact(allocator: std.mem.Allocator) !types.RunarArtifact {
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"00ac","asm":"",
        \\"abi":{"constructor":{"params":[{"name":"x","type":"bigint"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[{"paramIndex":0,"byteOffset":0}],"buildTimestamp":"2024-01-01"}
    ;
    return types.RunarArtifact.fromJson(allocator, json);
}

test "F-238: extractConstructorArgs refuses every malformed vector" {
    const allocator = std.testing.allocator;
    var artifact = try f238OneSlotArtifact(allocator);
    defer artifact.deinit();

    for (f238_malformed_vectors) |hex| {
        const result = extractConstructorArgs(&artifact, hex, allocator);
        try std.testing.expectError(error.MalformedScript, result);
    }
}

test "F-238: matchesArtifact refuses every malformed vector" {
    const allocator = std.testing.allocator;
    var artifact = try f238OneSlotArtifact(allocator);
    defer artifact.deinit();

    for (f238_malformed_vectors) |hex| {
        const result = matchesArtifact(&artifact, hex);
        try std.testing.expectError(error.MalformedScript, result);
    }
}

test "F-238: a valid OP_PUSHDATA1/2/4 push with exact length still decodes" {
    const allocator = std.testing.allocator;
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"00ac","asm":"",
        \\"abi":{"constructor":{"params":[{"name":"x","type":"ByteString"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[{"paramIndex":0,"byteOffset":0}],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    const cases = [_][]const u8{ "012aac", "4c012aac", "4d01002aac", "4e010000002aac" };
    for (cases) |script_hex| {
        var result = try extractConstructorArgs(&artifact, script_hex, allocator);
        defer {
            var it = result.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                entry.value_ptr.deinit(allocator);
            }
            result.deinit();
        }
        const got = result.get("x").?;
        try std.testing.expectEqualStrings("2a", got.bytes);
    }
}

test "extractConstructorArgs extracts int param" {
    const allocator = std.testing.allocator;
    // Script template: OP_0 (placeholder at byte 0) then "87" (OP_EQUAL)
    const json =
        \\{"contractName":"Test","version":"1","compilerVersion":"1.0","script":"0087","asm":"OP_0 OP_EQUAL",
        \\"abi":{"constructor":{"params":[{"name":"x","type":"int"}]},"methods":[{"name":"unlock","params":[],"isPublic":true}]},
        \\"stateFields":[],"constructorSlots":[{"paramIndex":0,"byteOffset":0}],"buildTimestamp":"2024-01-01"}
    ;
    var artifact = try types.RunarArtifact.fromJson(allocator, json);
    defer artifact.deinit();

    // On-chain script: OP_5 (55) + OP_EQUAL (87)
    var result = try extractConstructorArgs(&artifact, "5587", allocator);
    defer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    try std.testing.expectEqual(@as(usize, 1), result.count());
    const val = result.get("x").?;
    try std.testing.expectEqual(@as(i64, 5), val.int);
}

// A param referenced N times in the contract body emits N constructor slots.
// Every occurrence's encoded width shifts the offsets of everything after it,
// so the extractor must account for ALL occurrences — not just the first per
// param. Regression for a bug where slots were deduplicated by paramIndex
// BEFORE the offset walk, mis-reading every later slot whenever an earlier
// repeated value encoded wider than its 1-byte template placeholder.
//
// Template: ab <00> 7c <00> 7c <00> ac
//   offset 1: alpha (paramIndex 0)
//   offset 3: alpha again (paramIndex 0 — second reference)
//   offset 5: beta  (paramIndex 1)
const repeated_slot_artifact_json =
    \\{"contractName":"Repeat","version":"1","compilerVersion":"1.0","script":"ab007c007c00ac","asm":"",
    \\"abi":{"constructor":{"params":[{"name":"alpha","type":"int"},{"name":"beta","type":"int"}]},
    \\"methods":[{"name":"unlock","params":[],"isPublic":true}]},
    \\"stateFields":[],"constructorSlots":[{"paramIndex":0,"byteOffset":1},{"paramIndex":0,"byteOffset":3},{"paramIndex":1,"byteOffset":5}],
    \\"buildTimestamp":"2024-01-01"}
;

test "extractConstructorArgs reads slots AFTER a repeated wide value at the correct offsets" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, repeated_slot_artifact_json);
    defer artifact.deinit();

    // alpha = 500 → scriptnum push `02f401` (3 bytes, 2 wider than the
    // 1-byte template placeholder); beta = 7 → OP_7 (`57`).
    const resolved = "ab" ++ "02f401" ++ "7c" ++ "02f401" ++ "7c" ++ "57" ++ "ac";
    var result = try extractConstructorArgs(&artifact, resolved, allocator);
    defer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    try std.testing.expectEqual(@as(usize, 2), result.count());
    try std.testing.expectEqual(@as(i64, 500), result.get("alpha").?.int);
    // Before the fix the second alpha occurrence's +2 byte shift was dropped,
    // so beta was read from inside the second alpha push and decoded as 124.
    try std.testing.expectEqual(@as(i64, 7), result.get("beta").?.int);
}

test "extractConstructorArgs still extracts when the repeated value fits its placeholder width" {
    const allocator = std.testing.allocator;
    var artifact = try types.RunarArtifact.fromJson(allocator, repeated_slot_artifact_json);
    defer artifact.deinit();

    // alpha = 5 → OP_5 (1 byte, same width as the placeholder: zero shift).
    const resolved = "ab" ++ "55" ++ "7c" ++ "55" ++ "7c" ++ "57" ++ "ac";
    var result = try extractConstructorArgs(&artifact, resolved, allocator);
    defer {
        var it = result.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        result.deinit();
    }

    try std.testing.expectEqual(@as(i64, 5), result.get("alpha").?.int);
    try std.testing.expectEqual(@as(i64, 7), result.get("beta").?.int);
}
