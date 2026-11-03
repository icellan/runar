const runar = @import("runar");

// Directives -- Zig port of
// examples/ts/compiler-directives/Directives.runar.ts.
//
// The two compiler directives in their native Zig spelling (N-093): the type
// function EmbedAlways(T) keeps deployTag in the locking script although
// no method reads it, and the return type runar.Sighash(<FLAGS>)
// (which is `void` to the Zig compiler) declares the BIP-143 mode spendSingle
// commits to.
pub const Directives = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,
    deployTag: runar.EmbedAlways(runar.ByteString),

    pub fn init(pubKeyHash: runar.Addr, deployTag: runar.ByteString) Directives {
        return .{ .pubKeyHash = pubKeyHash, .deployTag = deployTag };
    }

    pub fn spendAll(self: *const Directives, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }

    pub fn spendSingle(self: *const Directives, sig: runar.Sig, pubKey: runar.PubKey) runar.Sighash("SINGLE|FORKID") {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
