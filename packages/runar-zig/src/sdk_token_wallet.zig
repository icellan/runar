const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");
const script_utils = @import("sdk_script_utils.zig");
const state_mod = @import("sdk_state.zig");

// ---------------------------------------------------------------------------
// TokenWallet — BSV-20/21 ordinal UTXO holder and helper functions
// ---------------------------------------------------------------------------
//
// Mirrors the TS/Go/Rust/Python/Ruby TokenWallet API. Holds references to a
// compiled artifact, a Provider, and a Signer, and offers UTXO filtering.
//
// No transfer/merge here, on purpose (N-239). The other five tiers'
// TokenWallet.transfer/merge drive a transfer(sig, to: Addr) /
// merge(sig, otherSupply, otherHolder) ABI that cannot be made sound —
// transfer cannot re-key the PubKey holder, and merge cannot authenticate its
// companion input (supply inflation) — and are deprecated there. Do not port
// them; use the token-ft example (FungibleTokenExample) with RunarContract.

pub const TokenWalletError = error{
    NoUtxos,
    ProviderError,
    SignerError,
    OutOfMemory,
    InsufficientBalance,
};

pub const TokenWallet = struct {
    allocator: std.mem.Allocator,
    artifact: *const types.RunarArtifact,
    provider: provider_mod.Provider,
    signer: signer_mod.Signer,

    pub fn init(
        allocator: std.mem.Allocator,
        artifact: *const types.RunarArtifact,
        provider: provider_mod.Provider,
        signer: signer_mod.Signer,
    ) TokenWallet {
        return .{
            .allocator = allocator,
            .artifact = artifact,
            .provider = provider,
            .signer = signer,
        };
    }

    /// Returns all token UTXOs associated with this wallet's signer address,
    /// filtered to only those whose locking script begins with the artifact's
    /// codePart prefix. Caller owns the returned slice and each UTXO.
    pub fn getUtxos(self: *TokenWallet, allocator: std.mem.Allocator) TokenWalletError![]types.UTXO {
        const addr = self.signer.getAddress(allocator) catch return TokenWalletError.SignerError;
        defer allocator.free(addr);

        const all = self.provider.getUtxos(allocator, addr) catch return TokenWalletError.ProviderError;
        defer {
            for (all) |*u| {
                var mu = u.*;
                mu.deinit(allocator);
            }
            allocator.free(all);
        }

        // N-076: the artifact script is the TEMPLATE; every slot (constructor
        // arg, codeSepIndex, code-part length) is a placeholder that
        // deployment replaces, so a raw prefix of it never matches a slotted
        // deployment. With constructor slots, use the slot-aware
        // matchesArtifact; a template with none is deployed verbatim, so its
        // literal prefix is exact.
        const prefix = self.artifact.script;
        const slotted = self.artifact.constructor_slots.len > 0;

        var filtered: std.ArrayListUnmanaged(types.UTXO) = .empty;
        errdefer {
            for (filtered.items) |*u| u.deinit(allocator);
            filtered.deinit(allocator);
        }

        for (all) |u| {
            const keep = blk: {
                if (prefix.len == 0 or u.script.len == 0) break :blk true;
                if (!slotted) {
                    if (u.script.len < prefix.len) break :blk false;
                    break :blk std.mem.eql(u8, u.script[0..prefix.len], prefix);
                }
                // N-317: any UTXO the provider lists is attacker-influenced; a
                // script that is not whole hex bytes is not an instance of this
                // contract.
                if (!script_utils.isHexBytes(u.script)) break :blk false;
                // matchesArtifact strips the state section only for artifacts
                // that declare state fields; cut it here for the rest.
                var code_hex: []const u8 = u.script;
                if (self.artifact.state_fields.len == 0) {
                    if (state_mod.findLastOpReturn(code_hex)) |pos| code_hex = code_hex[0..pos];
                }
                // A script that is not well-formed at the artifact's slot
                // offsets (F-238) is not an instance of this contract.
                break :blk script_utils.matchesArtifact(self.artifact, code_hex) catch false;
            };
            if (keep) {
                const cloned = u.clone(allocator) catch return TokenWalletError.OutOfMemory;
                filtered.append(allocator, cloned) catch return TokenWalletError.OutOfMemory;
            }
        }

        return filtered.toOwnedSlice(allocator) catch return TokenWalletError.OutOfMemory;
    }

    /// Pick a UTXO whose on-chain state holds at least `amount` balance.
    /// This wrapper assumes caller has separately decoded balance from state
    /// (full state-read requires the RunarContract API). It returns the first
    /// UTXO in `candidates`, or NoUtxos if empty.
    pub fn pickCandidate(candidates: []const types.UTXO) TokenWalletError!types.UTXO {
        if (candidates.len == 0) return TokenWalletError.NoUtxos;
        return candidates[0];
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const MockSigner = struct {
    addr: []const u8,

    fn getPublicKeyImpl(_: *anyopaque, allocator: std.mem.Allocator) signer_mod.SignerError![]u8 {
        return allocator.dupe(u8, "02" ++ ("00" ** 32)) catch return error.OutOfMemory;
    }
    fn getAddressImpl(ctx: *anyopaque, allocator: std.mem.Allocator) signer_mod.SignerError![]u8 {
        const self: *MockSigner = @ptrCast(@alignCast(ctx));
        return allocator.dupe(u8, self.addr) catch return error.OutOfMemory;
    }
    fn signImpl(_: *anyopaque, allocator: std.mem.Allocator, _: []const u8, _: usize, _: []const u8, _: i64, _: ?u32) signer_mod.SignerError![]u8 {
        return allocator.dupe(u8, "00" ** 72) catch return error.OutOfMemory;
    }

    const vtable = signer_mod.Signer.VTable{
        .getPublicKey = getPublicKeyImpl,
        .getAddress = getAddressImpl,
        .sign = signImpl,
    };

    fn signer(self: *MockSigner) signer_mod.Signer {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }
};

test "TokenWallet.getUtxos filters by artifact script prefix" {
    const allocator = std.testing.allocator;

    var mock_prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer mock_prov.deinit();
    try mock_prov.addUtxo("tokenAddr", .{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 1000,
        .script = "deadbeefcafebabe",
    });
    try mock_prov.addUtxo("tokenAddr", .{
        .txid = "bb" ** 32,
        .output_index = 0,
        .satoshis = 2000,
        .script = "11112222",
    });

    var mock_signer = MockSigner{ .addr = "tokenAddr" };

    // Artifact whose script prefix matches only the first UTXO.
    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "FungibleToken",
        .script = "deadbeef",
    };

    var tw = TokenWallet.init(
        allocator,
        &artifact,
        mock_prov.provider(),
        mock_signer.signer(),
    );

    const filtered = try tw.getUtxos(allocator);
    defer {
        for (filtered) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(filtered);
    }

    try std.testing.expectEqual(@as(usize, 1), filtered.len);
    try std.testing.expectEqual(@as(i64, 1000), filtered[0].satoshis);
}

test "TokenWallet.getUtxos returns all UTXOs when artifact has no script prefix" {
    const allocator = std.testing.allocator;

    var mock_prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer mock_prov.deinit();
    try mock_prov.addUtxo("anyAddr", .{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 500,
        .script = "1234",
    });

    var mock_signer = MockSigner{ .addr = "anyAddr" };

    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "X",
        .script = "",
    };

    var tw = TokenWallet.init(
        allocator,
        &artifact,
        mock_prov.provider(),
        mock_signer.signer(),
    );

    const filtered = try tw.getUtxos(allocator);
    defer {
        for (filtered) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(filtered);
    }

    try std.testing.expectEqual(@as(usize, 1), filtered.len);
}

// N-076: getUtxos must discover a deployed token contract with the slot-aware
// matcher (matchesArtifact), not a raw prefix of the template. The template
// carries a constructor slot, a codeSepIndex slot (baked as OP_1) and a
// codePartLenSlots field (the deployed code-part length), none of which a
// literal prefix of the template can equal.
//
// Proves: a deployed instance of such a template (with a state section) is
// found, while scripts that share the pre-slot prefix but differ after it,
// carry a wrong code-part length, or are unrelated are not.
// Does NOT prove: on-chain spendability of the matched UTXO, nor that an
// artifact with only codeSepIndex slots (no constructor slots) is matched --
// matchesArtifact itself compares such a template literally.

// bytes: 76 a9 [00] 88 [00] 75 04 [00000000] ac
//   ctor slot @2, codeSepIndex slot @4, codePartLen field @7
fn n076Discover(script: []const u8) !usize {
    const allocator = std.testing.allocator;
    var mock_prov = provider_mod.MockProvider.init(allocator, "testnet");
    defer mock_prov.deinit();
    try mock_prov.addUtxo("tokenAddr", .{
        .txid = "aa" ** 32,
        .output_index = 0,
        .satoshis = 1000,
        .script = script,
    });
    var mock_signer = MockSigner{ .addr = "tokenAddr" };

    var state_fields = [_]types.StateField{.{ .name = "", .type_name = "", .index = 1 }};
    var ctor_slots = [_]types.ConstructorSlot{.{ .param_index = 0, .byte_offset = 2 }};
    var cs_slots = [_]types.CodeSepIndexSlot{.{ .byte_offset = 4, .code_sep_index = 1 }};
    var len_slots = [_]types.CodePartLenSlot{.{ .byte_offset = 7 }};
    const artifact = types.RunarArtifact{
        .allocator = allocator,
        .contract_name = "FungibleToken",
        .script = "76a9" ++ "00" ++ "88" ++ "00" ++ "75" ++ "04" ++ "00000000" ++ "ac",
        .state_fields = &state_fields,
        .constructor_slots = &ctor_slots,
        .code_sep_index_slots = &cs_slots,
        .code_part_len_slots = &len_slots,
    };
    var tw = TokenWallet.init(allocator, &artifact, mock_prov.provider(), mock_signer.signer());
    const filtered = try tw.getUtxos(allocator);
    defer {
        for (filtered) |*u| {
            var mu = u.*;
            mu.deinit(allocator);
        }
        allocator.free(filtered);
    }
    return filtered.len;
}

test "N-076: getUtxos finds a deployed instance with constructor, codeSepIndex and code-part-length slots" {
    // supply = 02aabb, codeSepIndex baked as OP_1, code part is 14 bytes.
    try std.testing.expectEqual(@as(usize, 1), try n076Discover("76a9" ++ "02aabb" ++ "88" ++ "51" ++ "75" ++ "04" ++ "0e000000" ++ "ac" ++ "6a0100"));
}

test "N-076: getUtxos rejects scripts that only share the pre-slot prefix" {
    // differs after the slots
    try std.testing.expectEqual(@as(usize, 0), try n076Discover("76a9" ++ "02aabb" ++ "88" ++ "51" ++ "75" ++ "04" ++ "0e000000" ++ "ad" ++ "6a0100"));
    // wrong code-part length
    try std.testing.expectEqual(@as(usize, 0), try n076Discover("76a9" ++ "02aabb" ++ "88" ++ "51" ++ "75" ++ "04" ++ "0f000000" ++ "ac" ++ "6a0100"));
    // unrelated script
    try std.testing.expectEqual(@as(usize, 0), try n076Discover("76a914" ++ ("11" ** 20) ++ "88ac"));
}

test "TokenWallet.pickCandidate returns NoUtxos when empty" {
    const empty = [_]types.UTXO{};
    try std.testing.expectError(TokenWalletError.NoUtxos, TokenWallet.pickCandidate(&empty));
}
