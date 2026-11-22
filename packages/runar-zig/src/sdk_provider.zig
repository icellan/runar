const std = @import("std");
const bsvz = @import("bsvz");
const types = @import("sdk_types.zig");
const errors_mod = @import("sdk_errors.zig");
const deploy_mod = @import("sdk_deploy.zig");

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

/// Provider abstracts blockchain access for UTXO lookup and broadcast.
pub const Provider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getTransaction: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) ProviderError!types.TransactionData,
        broadcast: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8,
        getUtxos: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, address: []const u8) ProviderError![]types.UTXO,
        getContractUtxo: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, script_hash: []const u8) ProviderError!?types.UTXO,
        getNetwork: *const fn (ctx: *anyopaque) []const u8,
        getFeeRate: *const fn (ctx: *anyopaque) ProviderError!i64,
        getRawTransaction: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) ProviderError![]u8,
    };

    pub fn getTransaction(self: Provider, allocator: std.mem.Allocator, txid: []const u8) ProviderError!types.TransactionData {
        return self.vtable.getTransaction(self.ptr, allocator, txid);
    }

    pub fn broadcast(self: Provider, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8 {
        return self.vtable.broadcast(self.ptr, allocator, tx_hex);
    }

    pub fn getUtxos(self: Provider, allocator: std.mem.Allocator, address: []const u8) ProviderError![]types.UTXO {
        return self.vtable.getUtxos(self.ptr, allocator, address);
    }

    pub fn getContractUtxo(self: Provider, allocator: std.mem.Allocator, script_hash: []const u8) ProviderError!?types.UTXO {
        return self.vtable.getContractUtxo(self.ptr, allocator, script_hash);
    }

    pub fn getNetwork(self: Provider) []const u8 {
        return self.vtable.getNetwork(self.ptr);
    }

    pub fn getFeeRate(self: Provider) ProviderError!i64 {
        return self.vtable.getFeeRate(self.ptr);
    }

    pub fn getRawTransaction(self: Provider, allocator: std.mem.Allocator, txid: []const u8) ProviderError![]u8 {
        return self.vtable.getRawTransaction(self.ptr, allocator, txid);
    }
};

pub const ProviderError = error{
    NotFound,
    BroadcastFailed,
    NetworkError,
    OutOfMemory,
    /// DoS-bound: a UTXO returned by the provider carries a locking script
    /// larger than `errors_mod.MAX_SCRIPT_BYTES`. Inspect
    /// `errors_mod.last_error` for the structured limit/actual/context.
    ScriptSizeExceeded,
    /// MockProvider refused to acknowledge a broadcast (testing-gap
    /// remediation Phase A5). Inspect `MockProvider.lastRejection()` for the
    /// structured reason.
    BroadcastRejected,
};

// ---------------------------------------------------------------------------
// Broadcast validation (testing-gap remediation Phase A5)
// ---------------------------------------------------------------------------

/// Why a broadcast was refused. Zig errors carry no payload, so the reason is
/// exposed as a separate enum on the provider.
pub const RejectionReason = enum {
    none,
    /// The payload does not parse as a Bitcoin transaction at all.
    not_a_transaction,
    /// No spent outpoint is known to this provider, so validation would have
    /// checked NOTHING and passed vacuously.
    nothing_checked,
    /// Every input is known and the outputs exceed them.
    underfunded,
    /// An output script is over MAX_SCRIPT_BYTES.
    script_too_large,
    /// An input spends an outpoint an earlier accepted broadcast already
    /// spent, or the transaction spends one outpoint twice.
    double_spend,
};

/// What a validating broadcast actually checked.
///
/// `scripts_executed` is ALWAYS 0 in this tier and is present precisely so
/// that fact stays visible: Zig ships no Bitcoin Script VM (root CLAUDE.md,
/// "Off-chain Script VM" — the `bsvz` library's `script/engine.zig` does not
/// compile under the repo's Zig 0.16 toolchain, and project policy forbids
/// hand-rolling an interpreter). If a Zig ScriptVM ever lands, extend this
/// struct rather than silently implying coverage that does not exist.
pub const ValidationReport = struct {
    scripts_executed: usize = 0,
    known_inputs: usize = 0,
    total_inputs: usize = 0,
    value_conserved: bool = false,
};

const KnownOutpoint = struct {
    script: []const u8,
    satoshis: i64,
};

const ParsedInput = struct {
    /// Display-order (big-endian) txid hex, 64 chars.
    prev_txid: [64]u8,
    prev_vout: u32,
};

const ParsedOutput = struct {
    satoshis: i64,
    /// Slice into the caller-owned scratch buffer of lowercase script hex.
    script_hex: []const u8,
};

const ParsedTx = struct {
    inputs: []ParsedInput,
    outputs: []ParsedOutput,
    script_scratch: []u8,

    fn deinit(self: *ParsedTx, allocator: std.mem.Allocator) void {
        allocator.free(self.inputs);
        allocator.free(self.outputs);
        allocator.free(self.script_scratch);
    }
};

const ParseError = error{ NotATransaction, OutOfMemory };

fn readVarInt(bytes: []const u8, cur: *usize) ParseError!u64 {
    if (cur.* >= bytes.len) return ParseError.NotATransaction;
    const first = bytes[cur.*];
    cur.* += 1;
    switch (first) {
        0xfd => {
            if (cur.* + 2 > bytes.len) return ParseError.NotATransaction;
            const v = std.mem.readInt(u16, bytes[cur.*..][0..2], .little);
            cur.* += 2;
            return v;
        },
        0xfe => {
            if (cur.* + 4 > bytes.len) return ParseError.NotATransaction;
            const v = std.mem.readInt(u32, bytes[cur.*..][0..4], .little);
            cur.* += 4;
            return v;
        },
        0xff => {
            if (cur.* + 8 > bytes.len) return ParseError.NotATransaction;
            const v = std.mem.readInt(u64, bytes[cur.*..][0..8], .little);
            cur.* += 8;
            return v;
        },
        else => return first,
    }
}

/// Parse a raw transaction hex into its inputs (spent outpoints) and outputs
/// (value + locking script). Structural only — this tier cannot execute
/// Bitcoin Script.
fn parseTx(allocator: std.mem.Allocator, tx_hex: []const u8) ParseError!ParsedTx {
    if (tx_hex.len == 0 or tx_hex.len % 2 != 0) return ParseError.NotATransaction;
    const bytes = allocator.alloc(u8, tx_hex.len / 2) catch return ParseError.OutOfMemory;
    defer allocator.free(bytes);
    _ = std.fmt.hexToBytes(bytes, tx_hex) catch return ParseError.NotATransaction;

    var cur: usize = 0;
    if (bytes.len < 4) return ParseError.NotATransaction;
    cur += 4; // version

    const in_count = try readVarInt(bytes, &cur);
    if (in_count == 0 or in_count > 100_000) return ParseError.NotATransaction;
    var inputs = allocator.alloc(ParsedInput, @intCast(in_count)) catch return ParseError.OutOfMemory;
    errdefer allocator.free(inputs);

    var i: usize = 0;
    while (i < in_count) : (i += 1) {
        if (cur + 36 > bytes.len) return ParseError.NotATransaction;
        // On the wire the previous txid is internal (little-endian) order;
        // outpoint keys use the display (big-endian) txid.
        var txid_hex: [64]u8 = undefined;
        var b: usize = 0;
        while (b < 32) : (b += 1) {
            const src = bytes[cur + 31 - b];
            _ = std.fmt.bufPrint(txid_hex[b * 2 ..][0..2], "{x:0>2}", .{src}) catch unreachable;
        }
        cur += 32;
        const vout = std.mem.readInt(u32, bytes[cur..][0..4], .little);
        cur += 4;
        const script_len = try readVarInt(bytes, &cur);
        if (cur + script_len > bytes.len) return ParseError.NotATransaction;
        cur += @intCast(script_len); // scriptSig — not executable in this tier
        if (cur + 4 > bytes.len) return ParseError.NotATransaction;
        cur += 4; // sequence
        inputs[i] = .{ .prev_txid = txid_hex, .prev_vout = vout };
    }

    const out_count = try readVarInt(bytes, &cur);
    if (out_count > 100_000) return ParseError.NotATransaction;
    var outputs = allocator.alloc(ParsedOutput, @intCast(out_count)) catch return ParseError.OutOfMemory;
    errdefer allocator.free(outputs);

    // Every output script, hex-encoded, in one scratch buffer. Bounded by the
    // input hex length, so no unbounded allocation.
    var scratch = allocator.alloc(u8, tx_hex.len) catch return ParseError.OutOfMemory;
    errdefer allocator.free(scratch);
    var scratch_used: usize = 0;

    var o: usize = 0;
    while (o < out_count) : (o += 1) {
        if (cur + 8 > bytes.len) return ParseError.NotATransaction;
        const sats = std.mem.readInt(u64, bytes[cur..][0..8], .little);
        cur += 8;
        const script_len = try readVarInt(bytes, &cur);
        if (cur + script_len > bytes.len) return ParseError.NotATransaction;
        const script_bytes = bytes[cur .. cur + @as(usize, @intCast(script_len))];
        cur += @intCast(script_len);
        const start = scratch_used;
        for (script_bytes) |sb| {
            _ = std.fmt.bufPrint(scratch[scratch_used..][0..2], "{x:0>2}", .{sb}) catch unreachable;
            scratch_used += 2;
        }
        outputs[o] = .{
            .satoshis = @intCast(sats),
            .script_hex = scratch[start..scratch_used],
        };
    }

    if (cur + 4 > bytes.len) return ParseError.NotATransaction;
    cur += 4; // locktime
    if (cur != bytes.len) return ParseError.NotATransaction; // trailing garbage

    return .{ .inputs = inputs, .outputs = outputs, .script_scratch = scratch };
}

// ---------------------------------------------------------------------------
// MockProvider — in-memory provider for testing
// ---------------------------------------------------------------------------

/// MockProvider is an in-memory provider for unit tests and local development.
///
/// Broadcast validation is DEFAULT-ON (testing-gap remediation Phase A5). This
/// tier has NO Bitcoin Script VM, so it makes no script-validity claim — see
/// `validateBroadcast` for exactly what it does and does not check, and
/// README "How fund-path tests fail closed in the Zig tier".
pub const MockProvider = struct {
    allocator: std.mem.Allocator,
    utxos: std.StringHashMap(std.ArrayListUnmanaged(types.UTXO)),
    raw_transactions: std.StringHashMap([]const u8),
    broadcast_count: u32 = 0,
    broadcasted_txs: std.ArrayListUnmanaged([]const u8),
    network: []const u8,
    fee_rate: i64 = 100,
    /// Gates the fail-closed check in `broadcast`. Default true; the opt-out is
    /// governed by `always_ack_allowlist.json` (see
    /// `src/sdk_always_ack_allowlist_test.zig`).
    validate_broadcasts: bool = true,
    /// "txid:vout" -> script + value for every outpoint this provider knows.
    known_outpoints: std.StringHashMap(KnownOutpoint),
    last_report: ValidationReport = .{},
    last_rejection: RejectionReason = .none,
    /// "txid:vout" -> real txid (display hex) of the accepted broadcast that
    /// spent it. Checked on EVERY broadcast, whatever `validate_broadcasts`
    /// says: a node refuses a second transaction spending an outpoint already
    /// spent.
    spent_outpoints: std.StringHashMap([64]u8),
    /// Real txid of every accepted broadcast -> the (owned) txid this provider
    /// returned for it: re-broadcasting the identical tx is idempotent.
    accepted_txids: std.AutoHashMap([64]u8, []u8),

    pub fn init(allocator: std.mem.Allocator, network: []const u8) MockProvider {
        return .{
            .allocator = allocator,
            .utxos = std.StringHashMap(std.ArrayListUnmanaged(types.UTXO)).init(allocator),
            .raw_transactions = std.StringHashMap([]const u8).init(allocator),
            .broadcasted_txs = .empty,
            .network = if (network.len > 0) network else "testnet",
            .known_outpoints = std.StringHashMap(KnownOutpoint).init(allocator),
            .spent_outpoints = std.StringHashMap([64]u8).init(allocator),
            .accepted_txids = std.AutoHashMap([64]u8, []u8).init(allocator),
        };
    }

    /// A MockProvider whose `broadcast` never validates — the pre-Phase-A5
    /// behaviour.
    ///
    /// FOR ALLOWLISTED TESTS ONLY: every `*_test.zig` (and any in-module test
    /// block) that calls this, or `disableBroadcastValidation`, must carry a
    /// matching entry in `always_ack_allowlist.json`, enforced by
    /// `src/sdk_always_ack_allowlist_test.zig`. Fund-path deploy/call tests
    /// must not use it.
    pub fn initAlwaysAck(allocator: std.mem.Allocator, network: []const u8) MockProvider {
        var m = MockProvider.init(allocator, network);
        m.validate_broadcasts = false;
        return m;
    }

    /// Turn the fail-closed `broadcast` check on or off. Passing false is an
    /// allowlisted opt-out — see `initAlwaysAck`.
    pub fn enableBroadcastValidation(self: *MockProvider, enabled: bool) void {
        self.validate_broadcasts = enabled;
    }

    /// Restore the legacy always-ack `broadcast`. Allowlisted opt-out.
    pub fn disableBroadcastValidation(self: *MockProvider) void {
        self.validate_broadcasts = false;
    }

    /// Report from the most recent validating `broadcast`. Exposed so a test
    /// can assert its gate is NOT vacuous.
    pub fn lastValidationReport(self: *const MockProvider) ValidationReport {
        return self.last_report;
    }

    /// Number of spent outpoints the most recent validating broadcast actually
    /// recognised and checked.
    pub fn lastValidatedInputCount(self: *const MockProvider) usize {
        return self.last_report.known_inputs;
    }

    /// Why the most recent `broadcast` was refused (`.none` if it was not).
    pub fn lastRejection(self: *const MockProvider) RejectionReason {
        return self.last_rejection;
    }

    pub fn deinit(self: *MockProvider) void {
        var utxo_it = self.utxos.iterator();
        while (utxo_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |*u| u.deinit(self.allocator);
            entry.value_ptr.deinit(self.allocator);
        }
        self.utxos.deinit();

        var raw_it = self.raw_transactions.iterator();
        while (raw_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.raw_transactions.deinit();

        var known_it = self.known_outpoints.iterator();
        while (known_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.script);
        }
        self.known_outpoints.deinit();

        var spent_it = self.spent_outpoints.iterator();
        while (spent_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.spent_outpoints.deinit();

        var acc_it = self.accepted_txids.valueIterator();
        while (acc_it.next()) |v| self.allocator.free(v.*);
        self.accepted_txids.deinit();

        for (self.broadcasted_txs.items) |tx| {
            self.allocator.free(tx);
        }
        self.broadcasted_txs.deinit(self.allocator);
    }

    /// Record an outpoint's script + value so broadcast validation can reason
    /// about it. Idempotent: re-registering the same outpoint replaces it.
    pub fn addKnownOutpoint(
        self: *MockProvider,
        txid: []const u8,
        vout: i32,
        script: []const u8,
        satoshis: i64,
    ) !void {
        if (txid.len == 0 or script.len == 0) return;
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ txid, vout });
        errdefer self.allocator.free(key);
        const script_copy = try self.allocator.dupe(u8, script);
        errdefer self.allocator.free(script_copy);
        const gop = try self.known_outpoints.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(key);
            self.allocator.free(gop.value_ptr.script);
        }
        gop.value_ptr.* = .{ .script = script_copy, .satoshis = satoshis };
    }

    /// Add a UTXO for the given address.
    pub fn addUtxo(self: *MockProvider, address: []const u8, utxo: types.UTXO) !void {
        const key = try self.allocator.dupe(u8, address);
        errdefer self.allocator.free(key);
        const gop = try self.utxos.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(key);
        } else {
            gop.value_ptr.* = .empty;
        }
        try gop.value_ptr.append(self.allocator, try utxo.clone(self.allocator));
        try self.addKnownOutpoint(utxo.txid, utxo.output_index, utxo.script, utxo.satoshis);
    }

    /// Add a raw transaction hex by txid.
    pub fn addRawTransaction(self: *MockProvider, txid: []const u8, raw_hex: []const u8) !void {
        const key = try self.allocator.dupe(u8, txid);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, raw_hex);
        try self.raw_transactions.put(key, val);
    }

    /// Get the list of broadcasted transaction hex strings.
    pub fn getBroadcastedTxs(self: *const MockProvider) []const []const u8 {
        return self.broadcasted_txs.items;
    }

    /// Return a Provider interface backed by this MockProvider.
    pub fn provider(self: *MockProvider) Provider {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Provider.VTable{
        .getTransaction = getTransactionImpl,
        .broadcast = broadcastImpl,
        .getUtxos = getUtxosImpl,
        .getContractUtxo = getContractUtxoImpl,
        .getNetwork = getNetworkImpl,
        .getFeeRate = getFeeRateImpl,
        .getRawTransaction = getRawTransactionImpl,
    };

    fn getTransactionImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) ProviderError!types.TransactionData {
        return ProviderError.NotFound;
    }

    /// Fail-closed broadcast validation (testing-gap remediation Phase A5).
    ///
    /// WHAT THIS CHECKS — and, just as importantly, what it does not.
    ///
    /// The Zig tier ships no Bitcoin Script VM: the `bsvz` library's
    /// `script/engine.zig` does not compile under the repo's Zig 0.16
    /// toolchain (`unreachable else prong` at engine.zig:1172) and
    /// `zig-pkg/` is a gitignored fetch cache, not patchable in-repo; project
    /// policy forbids hand-rolling an interpreter (root CLAUDE.md, "Off-chain
    /// Script VM"). So this makes NO claim about signature or covenant
    /// validity. It applies the checks available from the serialized bytes:
    ///
    ///   1. STRUCTURAL     — the payload must parse as a Bitcoin transaction.
    ///   2. NON-VACUITY    — at least one spent outpoint must be known here,
    ///                       so the gate can never pass by checking nothing.
    ///   3. VALUE CONSERVE — when every input is known, outputs <= inputs.
    ///   4. SCRIPT-SIZE    — every output script stays under MAX_SCRIPT_BYTES.
    ///
    /// Script-level correctness for this tier is proven VERTICALLY instead:
    /// absolute-hex pins against the peer tiers' goldens plus the on-chain
    /// integration spends in integration/zig.
    fn validateBroadcast(self: *MockProvider, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError!void {
        self.last_rejection = .none;
        self.last_report = .{};

        var parsed = parseTx(allocator, tx_hex) catch |err| switch (err) {
            ParseError.OutOfMemory => return ProviderError.OutOfMemory,
            ParseError.NotATransaction => {
                self.last_rejection = .not_a_transaction;
                return ProviderError.BroadcastRejected;
            },
        };
        defer parsed.deinit(allocator);

        var known_inputs: usize = 0;
        var total_known_in: i64 = 0;
        var all_inputs_known = true;

        for (parsed.inputs) |in| {
            var key_buf: [96]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}:{d}", .{ in.prev_txid, in.prev_vout }) catch {
                all_inputs_known = false;
                continue;
            };
            if (self.known_outpoints.get(key)) |ko| {
                known_inputs += 1;
                total_known_in += ko.satoshis;
            } else {
                all_inputs_known = false;
            }
        }

        var total_out: i64 = 0;
        for (parsed.outputs, 0..) |out, i| {
            var ctx_buf: [96]u8 = undefined;
            const c = std.fmt.bufPrint(&ctx_buf, "MockProvider.broadcast output {d}", .{i}) catch "MockProvider.broadcast";
            errors_mod.assertScriptHexUnderLimit(out.script_hex, errors_mod.MAX_SCRIPT_BYTES, c) catch {
                self.last_rejection = .script_too_large;
                return ProviderError.ScriptSizeExceeded;
            };
            total_out += out.satoshis;
        }

        self.last_report = .{
            .scripts_executed = 0, // this tier has no Script VM — see the note above
            .known_inputs = known_inputs,
            .total_inputs = parsed.inputs.len,
            .value_conserved = all_inputs_known,
        };

        if (known_inputs == 0) {
            // A gate that validates nothing is worse than no gate.
            self.last_rejection = .nothing_checked;
            return ProviderError.BroadcastRejected;
        }
        if (all_inputs_known and total_out > total_known_in) {
            self.last_rejection = .underfunded;
            return ProviderError.BroadcastRejected;
        }
    }

    /// Double-spend gate, independent of `validate_broadcasts`. Refuses a
    /// transaction that spends one outpoint twice, or an outpoint an earlier
    /// accepted broadcast spent. Re-broadcasting the identical transaction is
    /// not a conflict (a node treats it as already known). Returns the real
    /// txid; `parsed` carries the input outpoints.
    fn checkDoubleSpend(self: *MockProvider, allocator: std.mem.Allocator, tx_hex: []const u8, parsed: *const ParsedTx) ProviderError![64]u8 {
        const spending_txid = realTxid(allocator, tx_hex) catch |err| switch (err) {
            error.OutOfMemory => return ProviderError.OutOfMemory,
            else => {
                self.last_rejection = .not_a_transaction;
                return ProviderError.BroadcastRejected;
            },
        };
        for (parsed.inputs, 0..) |in, i| {
            for (parsed.inputs[0..i]) |prev| {
                if (std.mem.eql(u8, &prev.prev_txid, &in.prev_txid) and prev.prev_vout == in.prev_vout) {
                    self.last_rejection = .double_spend;
                    return ProviderError.BroadcastRejected;
                }
            }
            var key_buf: [96]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}:{d}", .{ in.prev_txid, in.prev_vout }) catch unreachable;
            if (self.spent_outpoints.get(key)) |_| {
                if (!self.accepted_txids.contains(spending_txid)) {
                    self.last_rejection = .double_spend;
                    return ProviderError.BroadcastRejected;
                }
            }
        }
        return spending_txid;
    }

    fn broadcastImpl(ctx: *anyopaque, allocator: std.mem.Allocator, tx_hex: []const u8) ProviderError![]u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        self.last_rejection = .none;
        // A payload that does not parse spends no outpoint, so the gate has
        // nothing to check; validation (when on) refuses it as not a
        // transaction, and the always-ack opt-out keeps acking it.
        var gate_parsed: ?ParsedTx = parseTx(allocator, tx_hex) catch |err| switch (err) {
            ParseError.OutOfMemory => return ProviderError.OutOfMemory,
            ParseError.NotATransaction => null,
        };
        defer if (gate_parsed) |*gp| gp.deinit(allocator);
        if (self.validate_broadcasts) {
            try self.validateBroadcast(allocator, tx_hex);
        }
        var spending_txid: [64]u8 = undefined;
        if (gate_parsed) |*gp| spending_txid = try self.checkDoubleSpend(allocator, tx_hex, gp);
        // Re-broadcasting a tx already accepted is idempotent, as on a node:
        // same txid, nothing registered twice. It is still validated above, so
        // a tx an always-ack provider acked is not waved through once
        // validation is on.
        if (gate_parsed != null) {
            if (self.accepted_txids.get(spending_txid)) |prior| {
                return allocator.dupe(u8, prior) catch return ProviderError.OutOfMemory;
            }
        }
        // Accepted: its inputs are now spent.
        const spent_inputs: []const ParsedInput = if (gate_parsed) |gp| gp.inputs else &.{};
        for (spent_inputs) |in| {
            const key = std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ in.prev_txid, in.prev_vout }) catch
                return ProviderError.OutOfMemory;
            const gop = self.spent_outpoints.getOrPut(key) catch {
                self.allocator.free(key);
                return ProviderError.OutOfMemory;
            };
            if (gop.found_existing) self.allocator.free(key);
            gop.value_ptr.* = spending_txid;
        }
        const stored_hex = allocator.dupe(u8, tx_hex) catch return ProviderError.OutOfMemory;
        self.broadcasted_txs.append(self.allocator, stored_hex) catch {
            allocator.free(stored_hex);
            return ProviderError.OutOfMemory;
        };
        self.broadcast_count += 1;

        // Generate deterministic fake txid
        const prefix = if (tx_hex.len > 16) tx_hex[0..16] else tx_hex;
        const fake_txid = mockHash64(allocator, self.broadcast_count, prefix) catch return ProviderError.OutOfMemory;

        // Store raw hex for later retrieval
        const txid_key = allocator.dupe(u8, fake_txid) catch return ProviderError.OutOfMemory;
        const raw_val = allocator.dupe(u8, tx_hex) catch {
            allocator.free(txid_key);
            return ProviderError.OutOfMemory;
        };
        self.raw_transactions.put(txid_key, raw_val) catch {
            allocator.free(txid_key);
            allocator.free(raw_val);
            return ProviderError.OutOfMemory;
        };

        // Register this tx's own outputs as known outpoints so a chained call
        // (spending the continuation this broadcast just created) is checkable.
        if (self.validate_broadcasts) {
            var parsed = parseTx(allocator, tx_hex) catch |err| switch (err) {
                ParseError.OutOfMemory => return ProviderError.OutOfMemory,
                // Unreachable in practice: validateBroadcast already parsed it.
                ParseError.NotATransaction => return fake_txid,
            };
            defer parsed.deinit(allocator);
            for (parsed.outputs, 0..) |out, i| {
                self.addKnownOutpoint(fake_txid, @intCast(i), out.script_hex, out.satoshis) catch
                    return ProviderError.OutOfMemory;
            }
        }

        if (gate_parsed) |*gp| {
            const owned = self.allocator.dupe(u8, fake_txid) catch return ProviderError.OutOfMemory;
            self.accepted_txids.put(spending_txid, owned) catch {
                self.allocator.free(owned);
                return ProviderError.OutOfMemory;
            };
            try self.listNewP2pkhOutputs(fake_txid, gp);
        }

        return fake_txid;
    }

    /// A P2PKH output paying an address this provider lists (e.g. the change
    /// of a deploy) is a new UTXO of that address, as a node's listing would
    /// show it, so a later call can be funded from it.
    fn listNewP2pkhOutputs(self: *MockProvider, txid: []const u8, parsed: *const ParsedTx) ProviderError!void {
        var it = self.utxos.iterator();
        while (it.next()) |entry| {
            const p2pkh = deploy_mod.buildP2PKHScript(self.allocator, entry.key_ptr.*) catch |err| switch (err) {
                error.OutOfMemory => return ProviderError.OutOfMemory,
                else => continue, // a test label, not a real address
            };
            defer self.allocator.free(p2pkh);
            for (parsed.outputs, 0..) |out, i| {
                if (!std.ascii.eqlIgnoreCase(out.script_hex, p2pkh)) continue;
                const u = types.UTXO{
                    .txid = self.allocator.dupe(u8, txid) catch return ProviderError.OutOfMemory,
                    .output_index = @intCast(i),
                    .satoshis = out.satoshis,
                    .script = self.allocator.dupe(u8, out.script_hex) catch return ProviderError.OutOfMemory,
                };
                entry.value_ptr.append(self.allocator, u) catch return ProviderError.OutOfMemory;
            }
        }
    }

    fn getUtxosImpl(ctx: *anyopaque, allocator: std.mem.Allocator, address: []const u8) ProviderError![]types.UTXO {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        const list = self.utxos.get(address) orelse return allocator.alloc(types.UTXO, 0) catch return ProviderError.OutOfMemory;
        // DoS-bound: reject pathological UTXO scripts BEFORE handing to caller.
        for (list.items) |u| {
            if (u.script.len == 0) continue;
            var ctx_buf: [256]u8 = undefined;
            const c = std.fmt.bufPrint(&ctx_buf, "MockProvider.getUtxos({s})", .{address}) catch "MockProvider.getUtxos";
            errors_mod.assertScriptHexUnderLimit(u.script, errors_mod.MAX_SCRIPT_BYTES, c) catch return ProviderError.ScriptSizeExceeded;
        }
        // An outpoint an accepted broadcast spent is no longer a UTXO (a node's
        // listing would not return it either).
        var result = std.ArrayListUnmanaged(types.UTXO).empty;
        errdefer {
            for (result.items) |*u| u.deinit(allocator);
            result.deinit(allocator);
        }
        for (list.items) |u| {
            var key_buf: [160]u8 = undefined;
            const key = std.fmt.bufPrint(&key_buf, "{s}:{d}", .{ u.txid, u.output_index }) catch "";
            if (self.spent_outpoints.contains(key)) continue;
            const c = u.clone(allocator) catch return ProviderError.OutOfMemory;
            result.append(allocator, c) catch {
                var cc = c;
                cc.deinit(allocator);
                return ProviderError.OutOfMemory;
            };
        }
        return result.toOwnedSlice(allocator) catch return ProviderError.OutOfMemory;
    }

    fn getContractUtxoImpl(_: *anyopaque, _: std.mem.Allocator, _: []const u8) ProviderError!?types.UTXO {
        // MockProvider has no contract-utxo map; nothing to guard.
        return null;
    }

    fn getNetworkImpl(ctx: *anyopaque) []const u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        return self.network;
    }

    fn getFeeRateImpl(ctx: *anyopaque) ProviderError!i64 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        return self.fee_rate;
    }

    fn getRawTransactionImpl(ctx: *anyopaque, allocator: std.mem.Allocator, txid: []const u8) ProviderError![]u8 {
        const self: *MockProvider = @ptrCast(@alignCast(ctx));
        const raw = self.raw_transactions.get(txid) orelse return ProviderError.NotFound;
        return allocator.dupe(u8, raw) catch return ProviderError.OutOfMemory;
    }
};

/// The real txid of a raw transaction: double SHA-256, display (reversed) hex.
fn realTxid(allocator: std.mem.Allocator, tx_hex: []const u8) ![64]u8 {
    if (tx_hex.len % 2 != 0) return error.InvalidLength;
    const bytes = try allocator.alloc(u8, tx_hex.len / 2);
    defer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, tx_hex);
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var h1: [32]u8 = undefined;
    Sha256.hash(bytes, &h1, .{});
    var h2: [32]u8 = undefined;
    Sha256.hash(&h1, &h2, .{});
    const digits = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (0..32) |i| {
        const b = h2[31 - i];
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0x0f];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Deterministic mock hash (produces a 64-char hex string like a txid)
// ---------------------------------------------------------------------------

fn mockHash64(allocator: std.mem.Allocator, count: u32, prefix: []const u8) ![]u8 {
    var h0: u32 = 0x6a09e667;
    var h1: u32 = 0xbb67ae85;
    var h2: u32 = 0x3c6ef372;
    var h3: u32 = 0xa54ff53a;

    // Mix in count
    const count_str_buf = std.fmt.allocPrint(allocator, "mock-broadcast-{d}-", .{count}) catch return error.OutOfMemory;
    defer allocator.free(count_str_buf);
    for (count_str_buf) |c| {
        h0 = imul32(h0 ^ @as(u32, c), 0x01000193);
        h1 = imul32(h1 ^ @as(u32, c), 0x01000193);
        h2 = imul32(h2 ^ @as(u32, c), 0x01000193);
        h3 = imul32(h3 ^ @as(u32, c), 0x01000193);
    }
    for (prefix) |c| {
        h0 = imul32(h0 ^ @as(u32, c), 0x01000193);
        h1 = imul32(h1 ^ @as(u32, c), 0x01000193);
        h2 = imul32(h2 ^ @as(u32, c), 0x01000193);
        h3 = imul32(h3 ^ @as(u32, c), 0x01000193);
    }

    const parts = [8]u32{ h0, h1, h2, h3, h0 ^ h2, h1 ^ h3, h0 ^ h1, h2 ^ h3 };
    var result = try allocator.alloc(u8, 64);
    var pos: usize = 0;
    for (parts) |p| {
        _ = std.fmt.bufPrint(result[pos .. pos + 8], "{x:0>8}", .{p}) catch unreachable;
        pos += 8;
    }
    return result;
}

fn imul32(a: u32, b: u32) u32 {
    return a *% b;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "MockProvider returns UTXOs and broadcasts" {
    const allocator = std.testing.allocator;
    var mock = MockProvider.init(allocator, "testnet");
    defer mock.deinit();

    try mock.addUtxo("addr1", .{
        .txid = "aabb",
        .output_index = 0,
        .satoshis = 1000,
        .script = "76a914",
    });

    var prov = mock.provider();

    const utxos = try prov.getUtxos(allocator, "addr1");
    defer {
        for (utxos) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(utxos);
    }
    try std.testing.expectEqual(@as(usize, 1), utxos.len);
    try std.testing.expectEqual(@as(i64, 1000), utxos[0].satoshis);

    // Phase A5: broadcast is fail-closed, so it must be handed a REAL
    // transaction whose spent outpoint the provider knows. This previously
    // broadcast the 5-byte string "0100000000" — not a transaction — and
    // asserted success.
    try mock.addKnownOutpoint("aa" ** 32, 0, "51", 10_000);
    const raw_tx = "01000000" ++ "01" ++ ("aa" ** 32) ++ "00000000" ++ "00" ++ "ffffffff" ++
        "01" ++ "2823000000000000" ++ "0151" ++ "00000000";
    const txid = try prov.broadcast(allocator, raw_tx);
    defer allocator.free(txid);
    try std.testing.expectEqual(@as(usize, 64), txid.len);
    try std.testing.expectEqual(@as(usize, 1), mock.lastValidatedInputCount());

    const fee_rate = try prov.getFeeRate();
    try std.testing.expectEqual(@as(i64, 100), fee_rate);
}
