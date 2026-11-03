const runar = @import("runar");

// WalletToken -- the token ABI the SDKs' `TokenWallet` helper is written for.
//
// `TokenWallet` (TS, Go, Rust, Python, Ruby SDKs) assumes a stateful contract
// with state `supply` and `holder`, a `transfer(sig, to: Addr)` method and a
// `merge(sig, otherSupply, otherHolder)` method. This is that contract, so the
// wallet has something real to drive. See `examples/ts/token-wallet-naive-INSECURE/WalletToken.runar.ts`
// for the full rationale.
//
// NOT A SOUND TOKEN -- hence `naive-INSECURE`. Two limits follow from the ABI
// itself and cannot be fixed without changing it:
//
// - `transfer` cannot hand the token to `to`: `holder` is a PubKey (needed by
//   `checkSig`), `to` is an Addr (a hash160), and the method receives no
//   public key to store. It authorises the spend and checks `to` is 20 bytes;
//   the continuation keeps the same holder.
// - `merge` cannot authenticate its companion input. Nothing in
//   `(sig, otherSupply, otherHolder)` binds another input's outpoint or
//   script, so the holder can call `merge` on ONE input with a made-up
//   `otherSupply` and inflate the supply. TokenWallet spends both inputs, each
//   carrying the other's values, and `hashOutputs` forces them to agree --
//   but the contract does not REQUIRE a second input.
//
// For a token whose transfer re-keys the owner and whose merge proves its
// companion (parent-tx walk over `allPrevouts`), see `examples/zig/token-ft/`.
pub const WalletToken = struct {
    pub const Contract = runar.StatefulSmartContract;

    supply: i64 = 0,
    holder: runar.PubKey = runar.hexToBytes("000000000000000000000000000000000000000000000000000000000000000000"),

    pub fn init(supply: i64, holder: runar.PubKey) WalletToken {
        return .{ .supply = supply, .holder = holder };
    }

    pub fn transfer(self: *const WalletToken, sig: runar.Sig, to: runar.Addr) void {
        runar.assert(runar.checkSig(sig, self.holder));
        runar.assert(runar.len(to) == 20);
    }

    pub fn merge(self: *WalletToken, sig: runar.Sig, otherSupply: i64, otherHolder: runar.PubKey) void {
        runar.assert(runar.checkSig(sig, self.holder));
        runar.assert(runar.bytesEq(otherHolder, self.holder));
        runar.assert(otherSupply >= 0);
        self.supply = self.supply + otherSupply;
    }
};
