 pragma runar ^0.1.0;

/// @title FungibleToken
/// @notice A UTXO-based fungible token using Runar's multi-output (addOutput) facility.
/// Demonstrates how to model divisible token balances that can be split, transferred, and
/// merged -- similar to colored coins or SLP-style tokens but enforced entirely by Bitcoin Script.
/// @dev UTXO token model vs account model:
/// Unlike Ethereum ERC-20 where balances live in a global mapping, each token "balance" here
/// is a separate UTXO. The UTXO carries state: the current owner (PubKey), balance (bigint),
/// mergeBalance (bigint), and an immutable tokenId (ByteString). Transferring tokens means
/// spending one UTXO and creating new ones with updated state.
///
/// Operations:
///   transfer -- Split: 1 UTXO -> 2 UTXOs (recipient + change back to sender)
///   send     -- Simple send: 1 UTXO -> 1 UTXO (full balance to new owner)
///   merge    -- Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).
///
/// Companion-parent merge (W8 / SoloMerge): authenticates the companion via
/// otherParentTx. Input count is not identity. Pin:
/// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
///
/// The output stores both individual balances (balance and mergeBalance) so they can
/// be independently verified. Subsequent operations use the sum as the available balance.
///
/// Authorization: All operations require the current owner's ECDSA signature via checkSig.
contract FungibleToken is StatefulSmartContract {
    PubKey owner;                    /// @notice Current owner's public key. Mutable -- updated on ownership transfer.
    bigint balance;                  /// @notice Primary token balance. Mutable -- adjusted on transfer/split/merge.
    bigint mergeBalance;             /// @notice Secondary balance slot used during merge for cross-input verification. Normally 0.
    ByteString immutable tokenId;    /// @notice Unique token identifier. Readonly -- baked into the locking script, cannot change.

    constructor(PubKey _owner, bigint _balance, bigint _mergeBalance, ByteString _tokenId) {
        owner = _owner;
        balance = _balance;
        mergeBalance = _mergeBalance;
        tokenId = _tokenId;
    }

    /// @notice Transfer tokens to a recipient. If the full balance is sent, produces 1 output;
    /// otherwise produces 2 outputs (recipient + change back to sender).
    /// @dev Uses addOutput to create continuation UTXOs in the spending transaction.
    /// addOutput(satoshis, ...stateValues) takes positional state values matching mutable
    /// properties in declaration order: owner, balance, mergeBalance.
    /// @param sig Current owner's signature (authorization)
    /// @param to Recipient's public key
    /// @param amount Number of tokens to send (must be > 0 and <= total available balance)
    /// @param outputSatoshis Satoshis to fund each output UTXO
    function transfer(Sig sig, PubKey to, bigint amount, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        bigint totalBalance = this.balance + this.mergeBalance;
        require(amount > 0);
        require(amount <= totalBalance);

        // First output: recipient receives `amount` tokens
        this.addOutput(outputSatoshis, to, amount, 0);
        // Second output: sender keeps the remaining balance as change (skip if fully spent)
        if (amount < totalBalance) {
            this.addOutput(outputSatoshis, this.owner, totalBalance - amount, 0);
        }
    }

    /// @notice Simple send: 1 UTXO -> 1 UTXO. Transfers the entire balance to a new owner.
    /// @dev Creates a single continuation UTXO with the same balance but a new owner.
    /// @param sig Current owner's signature (authorization)
    /// @param to New owner's public key
    /// @param outputSatoshis Satoshis to fund the output UTXO
    function send(Sig sig, PubKey to, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);

        this.addOutput(outputSatoshis, to, this.balance + this.mergeBalance, 0);
    }

    /// @notice Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).
    /// @param otherParentTx Full serialized parent transaction of the companion input
    function merge(Sig sig, bigint otherBalance, ByteString allPrevouts, ByteString otherParentTx, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        require(otherBalance >= 0);
        require(len(this.tokenId) > 0);

        ByteString pad00 = num2bin(0, 1);
        require(hash256(allPrevouts) == extractHashPrevouts(this.txPreimage));
        require(len(allPrevouts) >= 72);

        ByteString myOutpoint = extractOutpoint(this.txPreimage);
        ByteString firstOutpoint = substr(allPrevouts, 0, 36);
        ByteString secondOutpoint = substr(allPrevouts, 36, 36);
        ByteString companionOutpoint = firstOutpoint;
        if (myOutpoint == firstOutpoint) {
            companionOutpoint = secondOutpoint;
        } else {
            require(myOutpoint == secondOutpoint);
        }
        ByteString companionTxid = substr(companionOutpoint, 0, 32);
        bigint companionVout = bin2num(cat(substr(companionOutpoint, 32, 4), pad00));
        require(companionVout == 0);
        require(hash256(otherParentTx) == companionTxid);

        bigint inCount = bin2num(cat(substr(otherParentTx, 4, 1), pad00));
        require(inCount >= 1);
        require(inCount <= 3);
        bigint off = 5;
        if (0 < inCount) {
            bigint sl = bin2num(cat(substr(otherParentTx, off + 36, 1), pad00));
            require(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        if (1 < inCount) {
            bigint sl = bin2num(cat(substr(otherParentTx, off + 36, 1), pad00));
            require(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        if (2 < inCount) {
            bigint sl = bin2num(cat(substr(otherParentTx, off + 36, 1), pad00));
            require(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        bigint outCount = bin2num(cat(substr(otherParentTx, off, 1), pad00));
        require(outCount >= 1);
        bigint marker = bin2num(cat(substr(otherParentTx, off + 9, 1), pad00));
        require(marker == 253);
        bigint scriptLen = bin2num(cat(substr(otherParentTx, off + 10, 2), pad00));
        bigint scriptStart = off + 12;
        require(len(otherParentTx) >= scriptStart + scriptLen);
        ByteString companionScript = substr(otherParentTx, scriptStart, scriptLen);
        require(scriptLen > 49);

        ByteString sc = extractScriptCode(this.txPreimage);
        bigint scMarker = bin2num(cat(substr(sc, 0, 1), pad00));
        require(scMarker == 253);
        ByteString myBody = substr(sc, 3, len(sc) - 3);
        ByteString companionBody = substr(companionScript, 2, scriptLen - 2);
        require(len(myBody) == len(companionBody));
        require(len(myBody) > 49);
        require(substr(myBody, 0, len(myBody) - 49) == substr(companionBody, 0, len(companionBody) - 49));

        bigint otherPrimary = bin2num(cat(substr(companionScript, scriptLen - 16, 8), pad00));
        bigint otherMerge = bin2num(cat(substr(companionScript, scriptLen - 8, 8), pad00));
        require(otherPrimary + otherMerge == otherBalance);

        bigint myBalance = this.balance + this.mergeBalance;
        if (myOutpoint == firstOutpoint) {
            this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
        } else {
            this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
        }
    }
}
