// FungibleToken -- A UTXO-based fungible token using Runar's multi-output (add_output) facility.
//
// Demonstrates how to model divisible token balances that can be split, transferred, and
// merged -- similar to colored coins or SLP-style tokens but enforced entirely by Bitcoin Script.
//
// UTXO token model vs account model:
// Unlike Ethereum ERC-20 where balances live in a global mapping, each token "balance" here
// is a separate UTXO. The UTXO carries state: the current owner (PubKey), balance (bigint),
// merge_balance (bigint), and an immutable token_id (ByteString). Transferring tokens means
// spending one UTXO and creating new ones with updated state.
//
// Operations:
//   transfer -- Split: 1 UTXO -> 2 UTXOs (recipient + change back to sender)
//   send     -- Simple send: 1 UTXO -> 1 UTXO (full balance to new owner)
//   merge    -- Secure merge: 2 UTXOs -> 1 UTXO (consolidate two token UTXOs)
//
// Secure merge design:
// The merge uses position-dependent output construction verified via hash_prevouts.
// Each input reads its own balance from its locking script (verified by OP_PUSH_TX)
// and writes it to a specific slot in the output based on its position in the transaction.
// Since hash_outputs forces both inputs to agree on the exact same output, each input's
// claimed other_balance must equal the other input's real verified balance.
// This prevents the inflation attack where an attacker lies about other_balance.
//
// The output stores both individual balances (balance and merge_balance) so they can
// be independently verified. Subsequent operations use the sum as the available balance.
//
// Authorization: All operations require the current owner's ECDSA signature via check_sig.
module FungibleToken {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig, hash256, extract_hash_prevouts, extract_outpoint, substr};

    resource struct FungibleToken {
        owner: &mut PubKey,           // Current owner's public key. Mutable -- updated on ownership transfer.
        balance: &mut bigint,         // Primary token balance. Mutable -- adjusted on transfer/split/merge.
        merge_balance: &mut bigint,   // Secondary balance slot used during merge for cross-input verification. Normally 0.
        token_id: ByteString,         // Unique token identifier. Immutable -- baked into the locking script, cannot change.
    }

    // Transfer tokens to a recipient. If the full balance is sent, produces 1 output;
    // otherwise produces 2 outputs (recipient + change back to sender).
    //
    // Uses add_output to create continuation UTXOs in the spending transaction.
    // add_output(satoshis, ...state_values) takes positional state values matching mutable
    // properties in declaration order: owner, balance, merge_balance.
    //
    // Parameters:
    //   sig: current owner's signature (authorization)
    //   to: recipient's public key
    //   amount: number of tokens to send (must be > 0 and <= total available balance)
    //   output_satoshis: satoshis to fund each output UTXO
    public fun transfer(contract: &mut FungibleToken, sig: Sig, to: PubKey, amount: bigint, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        let total_balance: bigint = contract.balance + contract.merge_balance;
        assert!(amount > 0, 0);
        assert!(amount <= total_balance, 0);

        // First output: recipient receives `amount` tokens
        contract.add_output(output_satoshis, to, amount, 0);
        // Second output: sender keeps the remaining balance as change (skip if fully spent)
        if (amount < total_balance) {
            contract.add_output(output_satoshis, contract.owner, total_balance - amount, 0);
        }
    }

    // Simple send: 1 UTXO -> 1 UTXO. Transfers the entire balance to a new owner.
    //
    // Creates a single continuation UTXO with the same balance but a new owner.
    //
    // Parameters:
    //   sig: current owner's signature (authorization)
    //   to: new owner's public key
    //   output_satoshis: satoshis to fund the output UTXO
    public fun send(contract: &mut FungibleToken, sig: Sig, to: PubKey, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);

        contract.add_output(output_satoshis, to, contract.balance + contract.merge_balance, 0);
    }

    // Secure merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
    //
    // Why this is secure (anti-inflation proof):
    //
    // Each input reads its own balance from its locking script (contract.balance), which is
    // verified by OP_PUSH_TX — it cannot be faked. Each input writes its verified balance
    // to a specific output slot based on its position in the transaction.
    //
    // Position is derived from all_prevouts (verified against hash_prevouts in the
    // preimage, so it reflects the real transaction) and the input's own outpoint.
    //
    // The output has two balance slots: balance (slot 0) and merge_balance (slot 1).
    // Each input places its own verified balance in its slot, and the claimed other_balance
    // in the other slot:
    //
    //   Input 0 (balance=400): add_output(sats, owner, 400, other_balance_0)
    //   Input 1 (balance=600): add_output(sats, owner, other_balance_1, 600)
    //
    // Both inputs must produce byte-identical outputs (enforced by hash_outputs in BIP-143).
    // This forces:
    //   - slot 0: 400 == other_balance_1  ->  input 1 MUST pass 400
    //   - slot 1: other_balance_0 == 600  ->  input 0 MUST pass 600
    //
    // Any lie causes a hash_outputs mismatch and the transaction is rejected on-chain.
    // The inputs can be in any order — each self-discovers its position from the preimage.
    //
    // Parameters:
    //   sig: current owner's signature (authorization)
    //   other_balance: claimed balance of the other merging input
    //   all_prevouts: concatenated outpoints of all tx inputs (verified via hash_prevouts)
    //   output_satoshis: satoshis to fund the merged output UTXO
    public fun merge(contract: &mut FungibleToken, sig: Sig, other_balance: bigint, all_prevouts: ByteString, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        assert!(other_balance >= 0, 0);

        // Verify all_prevouts is authentic (matches the actual transaction inputs)
        assert!(hash256(all_prevouts) == extract_hash_prevouts(contract.tx_preimage), 0);

        // Determine position: am I the first contract input?
        let my_outpoint: ByteString = extract_outpoint(contract.tx_preimage);
        let first_outpoint: ByteString = substr(all_prevouts, 0, 36);
        let my_balance: bigint = contract.balance + contract.merge_balance;

        if (my_outpoint == first_outpoint) {
            // I'm input 0: my verified balance goes to slot 0
            contract.add_output(output_satoshis, contract.owner, my_balance, other_balance);
        } else {
            // I'm input 1: my verified balance goes to slot 1
            contract.add_output(output_satoshis, contract.owner, other_balance, my_balance);
        }
    }
}
