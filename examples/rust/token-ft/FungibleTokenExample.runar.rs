use runar::prelude::*;

/// A UTXO-based fungible token using Runar's multi-output (`add_output`) facility.
///
/// Demonstrates how to model divisible token balances that can be split, transferred, and
/// merged -- similar to colored coins or SLP-style tokens but enforced entirely by Bitcoin Script.
///
/// # UTXO token model vs account model
///
/// Unlike Ethereum ERC-20 where balances live in a global mapping, each token "balance" here
/// is a separate UTXO. The UTXO carries state: the current owner (`PubKey`), balance (`Bigint`),
/// and an immutable `token_id` (`ByteString`). Transferring tokens means spending one UTXO and
/// creating new ones with updated state.
///
/// # Operations
///
/// - `transfer` -- Split: 1 UTXO -> 2 UTXOs (recipient + change back to sender)
/// - `send`     -- Simple send: 1 UTXO -> 1 UTXO (full balance to new owner)
/// - `merge`    -- Secure merge: 2 UTXOs -> 1 UTXO (consolidate two token UTXOs)
///
/// # Secure merge design
///
/// The merge uses position-dependent output construction verified via `hash_prevouts`.
/// Each input reads its own balance from its locking script (verified by OP_PUSH_TX)
/// and writes it to a specific slot in the output based on its position in the transaction.
/// Since `hash_outputs` forces both inputs to agree on the exact same output, each input's
/// claimed `other_balance` must equal the other input's real verified balance.
/// This prevents the inflation attack where an attacker lies about `other_balance`.
///
/// The output stores both individual balances (`balance` and `merge_balance`) so they can
/// be independently verified. Subsequent operations use the sum as the available balance.
///
/// # Authorization
///
/// All operations require the current owner's ECDSA signature via `check_sig`.
#[runar::contract]
pub struct FungibleToken {
    /// Current owner's public key. Mutable -- updated when tokens are sent to a new owner.
    pub owner: PubKey,
    /// Primary token balance. Mutable -- adjusted on transfer/split/merge.
    pub balance: Bigint,
    /// Secondary balance slot used during merge for cross-input verification. Normally 0.
    pub merge_balance: Bigint,
    /// Unique token identifier. Readonly -- baked into the locking script at deploy time
    /// and cannot change, ensuring token identity is preserved across all transfers.
    #[readonly]
    pub token_id: ByteString,
    /// Sighash preimage injected by the compiler for `checkPreimage` verification.
    pub tx_preimage: SigHashPreimage,
}

#[runar::methods(FungibleToken)]
impl FungibleToken {
    /// Transfer tokens to a recipient. If the full balance is sent, produces 1 output;
    /// otherwise produces 2 outputs (recipient + change back to sender).
    ///
    /// Uses `add_output` to create continuation UTXOs in the spending transaction.
    /// `add_output(satoshis, ...state_values)` takes positional state values matching mutable
    /// properties in declaration order: owner, balance, merge_balance.
    ///
    /// # Parameters
    /// - `sig` - Current owner's signature (authorization)
    /// - `to` - Recipient's public key
    /// - `amount` - Number of tokens to send (must be > 0 and <= total available balance)
    /// - `output_satoshis` - Satoshis to fund each output UTXO
    #[public]
    pub fn transfer(&mut self, sig: &Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(output_satoshis >= 1);
        let total_balance = self.balance + self.merge_balance;
        assert!(amount > 0);
        assert!(amount <= total_balance);

        // First output: recipient receives `amount` tokens
        self.add_output(output_satoshis, to, amount, 0);
        // Second output: sender keeps the remaining balance as change (skip if fully spent)
        if amount < total_balance {
            let change_owner = self.owner.clone();
            let change_balance = total_balance - amount;
            self.add_output(output_satoshis, change_owner, change_balance, 0);
        }
    }

    /// Simple send: 1 UTXO -> 1 UTXO. Transfers the entire balance to a new owner.
    ///
    /// Creates a single continuation UTXO with the same balance but a new owner.
    ///
    /// # Parameters
    /// - `sig` - Current owner's signature (authorization)
    /// - `to` - New owner's public key
    /// - `output_satoshis` - Satoshis to fund the output UTXO
    #[public]
    pub fn send(&mut self, sig: &Sig, to: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(output_satoshis >= 1);
        self.add_output(output_satoshis, to, self.balance + self.merge_balance, 0);
    }

    /// Secure merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
    ///
    /// # Why this is secure (anti-inflation proof)
    ///
    /// Each input reads its own balance from its locking script (`self.balance`), which is
    /// verified by OP_PUSH_TX — it cannot be faked. Each input writes its verified balance
    /// to a specific output slot based on its position in the transaction.
    ///
    /// Position is derived from `all_prevouts` (verified against `hash_prevouts` in the
    /// preimage, so it reflects the real transaction) and the input's own outpoint.
    ///
    /// The output has two balance slots: `balance` (slot 0) and `merge_balance` (slot 1).
    /// Each input places its own verified balance in its slot, and the claimed `other_balance`
    /// in the other slot:
    ///
    /// ```text
    ///   Input 0 (balance=400): add_output(sats, owner, 400, other_balance_0)
    ///   Input 1 (balance=600): add_output(sats, owner, other_balance_1, 600)
    /// ```
    ///
    /// Both inputs must produce byte-identical outputs (enforced by `hash_outputs` in BIP-143).
    /// This forces:
    ///   - slot 0: 400 == other_balance_1  →  input 1 MUST pass 400
    ///   - slot 1: other_balance_0 == 600  →  input 0 MUST pass 600
    ///
    /// Any lie causes a `hash_outputs` mismatch and the transaction is rejected on-chain.
    /// The inputs can be in any order — each self-discovers its position from the preimage.
    ///
    /// # Parameters
    /// - `sig` - Current owner's signature (authorization)
    /// - `other_balance` - Claimed balance of the other merging input
    /// - `all_prevouts` - Concatenated outpoints of all tx inputs (verified via hash_prevouts)
    /// - `output_satoshis` - Satoshis to fund the merged output UTXO
    #[public]
    pub fn merge(&mut self, sig: &Sig, other_balance: Bigint, all_prevouts: ByteString, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(output_satoshis >= 1);
        assert!(other_balance >= 0);

        // Verify all_prevouts is authentic (matches the actual transaction inputs)
        assert!(hash256(&all_prevouts) == extract_hash_prevouts(&self.tx_preimage));

        // Determine position: am I the first contract input?
        let my_outpoint = extract_outpoint(&self.tx_preimage);
        let first_outpoint = substr(&all_prevouts, 0, 36);
        let my_balance = self.balance + self.merge_balance;
        let owner = self.owner.clone();

        if my_outpoint == first_outpoint {
            // I'm input 0: my verified balance goes to slot 0
            self.add_output(output_satoshis, owner, my_balance, other_balance);
        } else {
            // I'm input 1: my verified balance goes to slot 1
            self.add_output(output_satoshis, owner, other_balance, my_balance);
        }
    }
}
