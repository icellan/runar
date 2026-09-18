const runar = @import("runar");

pub const FungibleToken = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey = "000000000000000000000000000000000000000000000000000000000000000000",
    balance: i64 = 0,
    mergeBalance: i64 = 0,
    tokenId: runar.ByteString,

    pub fn init(owner: runar.PubKey, balance: i64, mergeBalance: i64, tokenId: runar.ByteString) FungibleToken {
        return .{
            .owner = owner,
            .balance = balance,
            .mergeBalance = mergeBalance,
            .tokenId = tokenId,
        };
    }

    pub fn transfer(
        self: *FungibleToken,
        ctx: runar.StatefulContext,
        sig: runar.Sig,
        to: runar.PubKey,
        amount: i64,
        outputSatoshis: i64,
    ) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        const totalBalance = self.balance + self.mergeBalance;
        runar.assert(amount > 0);
        runar.assert(amount <= totalBalance);

        ctx.addOutput(outputSatoshis, .{ to, amount, 0 });
        if (amount < totalBalance) {
            ctx.addOutput(outputSatoshis, .{ self.owner, totalBalance - amount, 0 });
        }
    }

    pub fn send(self: *FungibleToken, ctx: runar.StatefulContext, sig: runar.Sig, to: runar.PubKey, outputSatoshis: i64) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        ctx.addOutput(outputSatoshis, .{ to, self.balance + self.mergeBalance, 0 });
    }

    // Companion-parent merge (W8 / SoloMerge): authenticates the companion
    // via otherParentTx. Input count is not identity. Pin:
    // packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
    pub fn merge(
        self: *FungibleToken,
        ctx: runar.StatefulContext,
        sig: runar.Sig,
        otherBalance: i64,
        allPrevouts: runar.ByteString,
        otherParentTx: runar.ByteString,
        outputSatoshis: i64,
    ) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(outputSatoshis >= 1);
        runar.assert(otherBalance >= 0);
        runar.assert(runar.len(self.tokenId) > 0);

        const pad00 = runar.num2bin(0, 1);
        runar.assert(runar.bytesEq(runar.hash256(allPrevouts), runar.extractHashPrevouts(ctx.txPreimage)));
        runar.assert(runar.len(allPrevouts) >= 72);

        const myOutpoint = runar.extractOutpoint(ctx.txPreimage);
        const firstOutpoint = runar.substr(allPrevouts, 0, 36);
        const secondOutpoint = runar.substr(allPrevouts, 36, 36);
        var companionOutpoint = firstOutpoint;
        if (runar.bytesEq(myOutpoint, firstOutpoint)) {
            companionOutpoint = secondOutpoint;
        } else {
            runar.assert(runar.bytesEq(myOutpoint, secondOutpoint));
        }
        const companionTxid = runar.substr(companionOutpoint, 0, 32);
        const companionVout = runar.bin2num(runar.cat(runar.substr(companionOutpoint, 32, 4), pad00));
        runar.assert(companionVout == 0);
        runar.assert(runar.bytesEq(runar.hash256(otherParentTx), companionTxid));

        const inCount = runar.bin2num(runar.cat(runar.substr(otherParentTx, 4, 1), pad00));
        runar.assert(inCount >= 1);
        runar.assert(inCount <= 3);
        var off: i64 = 5;
        if (0 < inCount) {
            const sl = runar.bin2num(runar.cat(runar.substr(otherParentTx, off + 36, 1), pad00));
            runar.assert(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        if (1 < inCount) {
            const sl = runar.bin2num(runar.cat(runar.substr(otherParentTx, off + 36, 1), pad00));
            runar.assert(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        if (2 < inCount) {
            const sl = runar.bin2num(runar.cat(runar.substr(otherParentTx, off + 36, 1), pad00));
            runar.assert(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        const outCountPrefix = runar.bin2num(runar.cat(runar.substr(otherParentTx, off, 1), pad00));
        runar.assert(outCountPrefix != 254);
        runar.assert(outCountPrefix != 255);
        var outHdr: i64 = 1;
        var outCount = outCountPrefix;
        if (outCountPrefix == 253) {
            outCount = runar.bin2num(runar.cat(runar.substr(otherParentTx, off + 1, 2), pad00));
            outHdr = 3;
        }
        runar.assert(outCount >= 1);
        const marker = runar.bin2num(runar.cat(runar.substr(otherParentTx, off + outHdr + 8, 1), pad00));
        runar.assert(marker == 253);
        const scriptLen = runar.bin2num(runar.cat(runar.substr(otherParentTx, off + outHdr + 9, 2), pad00));
        const scriptStart = off + outHdr + 11;
        runar.assert(runar.len(otherParentTx) >= scriptStart + scriptLen);
        const companionScript = runar.substr(otherParentTx, scriptStart, scriptLen);
        runar.assert(scriptLen > 49);

        const sc = runar.extractScriptCode(ctx.txPreimage);
        const scMarker = runar.bin2num(runar.cat(runar.substr(sc, 0, 1), pad00));
        runar.assert(scMarker == 253);
        const myBody = runar.substr(sc, 3, runar.len(sc) - 3);
        const companionBody = runar.substr(companionScript, 2, scriptLen - 2);
        runar.assert(runar.len(myBody) == runar.len(companionBody));
        runar.assert(runar.len(myBody) > 49);
        runar.assert(runar.bytesEq(runar.substr(myBody, 0, runar.len(myBody) - 49), runar.substr(companionBody, 0, runar.len(companionBody) - 49)));

        const otherPrimary = runar.bin2num(runar.cat(runar.substr(companionScript, scriptLen - 16, 8), pad00));
        const otherMerge = runar.bin2num(runar.cat(runar.substr(companionScript, scriptLen - 8, 8), pad00));
        runar.assert(otherPrimary + otherMerge == otherBalance);

        const myBalance = self.balance + self.mergeBalance;
        if (runar.bytesEq(myOutpoint, firstOutpoint)) {
            ctx.addOutput(outputSatoshis, .{ self.owner, myBalance, otherBalance });
        } else {
            ctx.addOutput(outputSatoshis, .{ self.owner, otherBalance, myBalance });
        }
    }
};
