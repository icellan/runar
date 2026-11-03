//! N-267: `README.md`'s section 9c (~799-838) showed `deployWithWallet`
//! calling `contract.deploy`/`contract.call` through `WalletProvider` and
//! treating the result as a real broadcast txid. After N-260 (R100),
//! `WalletProvider.broadcastImpl` never touches the wallet and always
//! returns `error.BroadcastFailed` — there is no BRC-100 primitive that
//! relays an already-signed raw transaction verbatim, so that example is
//! now wrong: it would compile but fail at the broadcast step every time.
//!
//! This is a text-only check on README.md, mirroring
//! sdk_always_ack_allowlist_test.zig's package-root file read. It proves:
//!   1. The README no longer shows `deployWithWallet` (or `WalletProvider`
//!      passed to `contract.deploy`/`contract.call`) as if it returns a
//!      real on-chain txid in the BRC-100 wallet example.
//!   2. The README states the actual post-N-260 refusal, citing
//!      `sdk_wallet.zig`'s exact message.
//!
//! It does NOT prove that `WalletProvider.broadcast` actually refuses on
//! this branch — N-260 is not landed here (rem/N-267 branches off a point
//! before it), so `sdk_wallet.zig` still has the old fail-open
//! `broadcastImpl` that calls `wallet.createAction` and returns its txid.
//! The behavioural assertion for that is N-260's own test
//! (`sdk_r062_wallet_deploy_gate_test.zig`). This test only pins the
//! README's prose to the behaviour N-260 introduces; the refusal message
//! literal below is copied byte-exact from N-260's diff
//! (`WalletProvider.RAW_BROADCAST_UNSUPPORTED_MSG` in `sdk_wallet.zig`)
//! rather than imported, since that constant does not exist yet on this
//! branch.

const std = @import("std");

/// Byte-exact copy of `WalletProvider.RAW_BROADCAST_UNSUPPORTED_MSG`
/// (introduced by N-260, not yet landed on this branch — see module doc).
const RAW_BROADCAST_UNSUPPORTED_MSG = "raw broadcast unsupported by BRC-100; use an ARC/WhatsOnChain provider";

/// The stale pattern: assigning `deployWithWallet`'s result to a variable
/// named as if it were a usable txid. Specific to the actual call-site text
/// (not a loose "deployWithWallet" substring match), so a correct mention of
/// the function elsewhere in prose does not trip this.
const STALE_DEPLOY_TXID_PATTERN = "const deploy_txid = try runar.deployWithWallet(";

fn packageRoot(allocator: std.mem.Allocator) ![]u8 {
    const z = try std.Io.Dir.cwd().realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(z);
    return try allocator.dupe(u8, z);
}

fn readReadme(allocator: std.mem.Allocator, root: []const u8) ![]u8 {
    const path = try std.fs.path.join(allocator, &.{ root, "README.md" });
    defer allocator.free(path);
    return try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, allocator, .limited(4 * 1024 * 1024));
}

test "N-267 README no longer shows deployWithWallet returning a usable broadcast txid" {
    const allocator = std.testing.allocator;
    const root = try packageRoot(allocator);
    defer allocator.free(root);

    const text = try readReadme(allocator, root);
    defer allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, STALE_DEPLOY_TXID_PATTERN) == null);
}

test "N-267 README states WalletProvider's post-N-260 raw-broadcast refusal" {
    const allocator = std.testing.allocator;
    const root = try packageRoot(allocator);
    defer allocator.free(root);

    const text = try readReadme(allocator, root);
    defer allocator.free(text);

    try std.testing.expect(std.mem.indexOf(u8, text, RAW_BROADCAST_UNSUPPORTED_MSG) != null);
}
