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
///   merge    -- Merge: 2 UTXOs -> 1 UTXO (UNSOUND: does not authenticate a second token input; W8 / SoloMerge)
///
/// UNSOUND merge (W8 / SoloMerge): merge never asserts that a second token
/// covenant is an input of the spending transaction. hash256(allPrevouts) ==
/// extractHashPrevouts(preimage) only proves allPrevouts is the real prevout
/// list. A one-input spend takes the "I am input 0" arm and writes the
/// spender-chosen otherBalance into the successor. A P2PKH fee input filling
/// len(allPrevouts) == 72 does not close the hole. Pin:
/// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
/// For a construction that binds a specific companion input, see
/// examples/ts/companion-verifier/.
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

    /// @notice Merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
    ///
    /// @dev UNSOUND (W8 / SoloMerge): this method does not authenticate a second
    /// token input. The position-dependent slot construction below is the
    /// intended two-input argument; its premise (a second input running this
    /// covenant) is never checked. A one-input spend writes otherBalance into
    /// the successor. Pin:
    /// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
    ///
    /// What the script actually does, if two token inputs happen to be present:
    /// each input writes its own locking-script balance to a slot based on
    /// whether its outpoint is first in allPrevouts, and hashOutputs then
    /// forces those two inputs to agree. That is not a proof that a second
    /// token input exists.
    ///
    /// @param sig Current owner's signature (authorization)
    /// @param otherBalance Claimed balance of the other merging input
    /// @param allPrevouts Concatenated outpoints of all tx inputs (verified via hashPrevouts)
    /// @param outputSatoshis Satoshis to fund the merged output UTXO
    function merge(Sig sig, bigint otherBalance, ByteString allPrevouts, bigint outputSatoshis) public {
        require(checkSig(sig, this.owner));
        require(outputSatoshis >= 1);
        require(otherBalance >= 0);

        // Verify allPrevouts is authentic (matches the actual transaction inputs)
        require(hash256(allPrevouts) == extractHashPrevouts(this.txPreimage));

        // Determine position: am I the first contract input?
        ByteString myOutpoint = extractOutpoint(this.txPreimage);
        ByteString firstOutpoint = substr(allPrevouts, 0, 36);
        bigint myBalance = this.balance + this.mergeBalance;

        if (myOutpoint == firstOutpoint) {
            // I'm input 0: my verified balance goes to slot 0
            this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
        } else {
            // I'm input 1: my verified balance goes to slot 1
            this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
        }
    }
}
