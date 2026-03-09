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
///   merge    -- Secure merge: 2 UTXOs -> 1 UTXO (consolidate two token UTXOs)
///
/// Secure merge design:
/// The merge uses position-dependent output construction verified via hashPrevouts.
/// Each input reads its own balance from its locking script (verified by OP_PUSH_TX)
/// and writes it to a specific slot in the output based on its position in the transaction.
/// Since hashOutputs forces both inputs to agree on the exact same output, each input's
/// claimed otherBalance must equal the other input's real verified balance.
/// This prevents the inflation attack where an attacker lies about otherBalance.
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

    /// @notice Secure merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
    ///
    /// @dev Why this is secure (anti-inflation proof):
    ///
    /// Each input reads its own balance from its locking script (this.balance), which is
    /// verified by OP_PUSH_TX — it cannot be faked. Each input writes its verified balance
    /// to a specific output slot based on its position in the transaction.
    ///
    /// Position is derived from allPrevouts (verified against hashPrevouts in the
    /// preimage, so it reflects the real transaction) and the input's own outpoint.
    ///
    /// The output has two balance slots: balance (slot 0) and mergeBalance (slot 1).
    /// Each input places its own verified balance in its slot, and the claimed otherBalance
    /// in the other slot:
    ///
    ///   Input 0 (balance=400): addOutput(sats, owner, 400, otherBalance_0)
    ///   Input 1 (balance=600): addOutput(sats, owner, otherBalance_1, 600)
    ///
    /// Both inputs must produce byte-identical outputs (enforced by hashOutputs in BIP-143).
    /// This forces:
    ///   - slot 0: 400 == otherBalance_1  ->  input 1 MUST pass 400
    ///   - slot 1: otherBalance_0 == 600  ->  input 0 MUST pass 600
    ///
    /// Any lie causes a hashOutputs mismatch and the transaction is rejected on-chain.
    /// The inputs can be in any order — each self-discovers its position from the preimage.
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
