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
//   merge    -- Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).
//
// Companion-parent merge (W8 / SoloMerge): authenticates the companion via
// other_parent_tx. Input count is not identity. Pin:
// packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
//
// The output stores both individual balances (balance and merge_balance) so they can
// be independently verified. Subsequent operations use the sum as the available balance.
//
// Authorization: All operations require the current owner's ECDSA signature via check_sig.
module FungibleToken {
    use runar::types::{PubKey, Sig, ByteString};
    use runar::crypto::{check_sig, hash256, extract_hash_prevouts, extract_outpoint, extract_script_code, substr, cat, bin2num, num2bin, len};

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

    // Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).
    public fun merge(contract: &mut FungibleToken, sig: Sig, other_balance: bigint, all_prevouts: ByteString, other_parent_tx: ByteString, output_satoshis: bigint) {
        assert!(check_sig(sig, contract.owner), 0);
        assert!(output_satoshis >= 1, 0);
        assert!(other_balance >= 0, 0);
        assert!(len(contract.token_id) > 0, 0);

        let pad00: ByteString = num2bin(0, 1);
        assert!(hash256(all_prevouts) == extract_hash_prevouts(contract.tx_preimage), 0);
        assert!(len(all_prevouts) >= 72, 0);

        let my_outpoint: ByteString = extract_outpoint(contract.tx_preimage);
        let first_outpoint: ByteString = substr(all_prevouts, 0, 36);
        let second_outpoint: ByteString = substr(all_prevouts, 36, 36);
        let mut companion_outpoint: ByteString = first_outpoint;
        if (my_outpoint == first_outpoint) {
            companion_outpoint = second_outpoint;
        } else {
            assert!(my_outpoint == second_outpoint, 0);
        };
        let companion_txid: ByteString = substr(companion_outpoint, 0, 32);
        let companion_vout: bigint = bin2num(cat(substr(companion_outpoint, 32, 4), pad00));
        assert!(companion_vout == 0, 0);
        assert!(hash256(other_parent_tx) == companion_txid, 0);

        let in_count: bigint = bin2num(cat(substr(other_parent_tx, 4, 1), pad00));
        assert!(in_count >= 1, 0);
        assert!(in_count <= 3, 0);
        let mut off: bigint = 5;
        if (0 < in_count) {
            let sl: bigint = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00));
            assert!(sl < 253, 0);
            off = off + 36 + 1 + sl + 4;
        };
        if (1 < in_count) {
            let sl: bigint = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00));
            assert!(sl < 253, 0);
            off = off + 36 + 1 + sl + 4;
        };
        if (2 < in_count) {
            let sl: bigint = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00));
            assert!(sl < 253, 0);
            off = off + 36 + 1 + sl + 4;
        };
        let out_count: bigint = bin2num(cat(substr(other_parent_tx, off, 1), pad00));
        assert!(out_count >= 1, 0);
        let marker: bigint = bin2num(cat(substr(other_parent_tx, off + 9, 1), pad00));
        assert!(marker == 253, 0);
        let script_len: bigint = bin2num(cat(substr(other_parent_tx, off + 10, 2), pad00));
        let script_start: bigint = off + 12;
        assert!(len(other_parent_tx) >= script_start + script_len, 0);
        let companion_script: ByteString = substr(other_parent_tx, script_start, script_len);
        assert!(script_len > 49, 0);

        let sc: ByteString = extract_script_code(contract.tx_preimage);
        let sc_marker: bigint = bin2num(cat(substr(sc, 0, 1), pad00));
        assert!(sc_marker == 253, 0);
        let my_body: ByteString = substr(sc, 3, len(sc) - 3);
        let companion_body: ByteString = substr(companion_script, 2, script_len - 2);
        assert!(len(my_body) == len(companion_body), 0);
        assert!(len(my_body) > 49, 0);
        assert!(substr(my_body, 0, len(my_body) - 49) == substr(companion_body, 0, len(companion_body) - 49), 0);

        let other_primary: bigint = bin2num(cat(substr(companion_script, script_len - 16, 8), pad00));
        let other_merge: bigint = bin2num(cat(substr(companion_script, script_len - 8, 8), pad00));
        assert!(other_primary + other_merge == other_balance, 0);

        let my_balance: bigint = contract.balance + contract.merge_balance;
        if (my_outpoint == first_outpoint) {
            contract.add_output(output_satoshis, contract.owner, my_balance, other_balance);
        } else {
            contract.add_output(output_satoshis, contract.owner, other_balance, my_balance);
        }
    }
}
