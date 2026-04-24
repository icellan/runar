const std = @import("std");
const types = @import("sdk_types.zig");
const provider_mod = @import("sdk_provider.zig");
const signer_mod = @import("sdk_signer.zig");

// ---------------------------------------------------------------------------
// TokenWallet — BSV-20/21 ordinal UTXO holder and helper functions
// ---------------------------------------------------------------------------
//
// Mirrors the TS/Go/Rust/Python/Ruby TokenWallet API. Holds references to a
// compiled artifact, a Provider, and a Signer, and offers UTXO filtering
// and helpers for the common token-contract lifecycle (balance, transfer,
// merge). Full transfer/merge require the RunarContract high-level API,
// which is not yet consumed from this wrapper — see `prepareTransferUnlock`
// for a low-level building block intended for SDK users.

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

        const prefix = self.artifact.script;

        var filtered: std.ArrayListUnmanaged(types.UTXO) = .empty;
        errdefer {
            for (filtered.items) |*u| u.deinit(allocator);
            filtered.deinit(allocator);
        }

        for (all) |u| {
            const keep = blk: {
                if (prefix.len == 0 or u.script.len == 0) break :blk true;
                if (u.script.len < prefix.len) break :blk false;
                break :blk std.mem.eql(u8, u.script[0..prefix.len], prefix);
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

test "TokenWallet.pickCandidate returns NoUtxos when empty" {
    const empty = [_]types.UTXO{};
    try std.testing.expectError(TokenWalletError.NoUtxos, TokenWallet.pickCandidate(&empty));
}
