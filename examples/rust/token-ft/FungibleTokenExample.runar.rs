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
/// - `merge`    -- Merge: 2 UTXOs -> 1 UTXO (UNSOUND: does not authenticate a second token input; W8 / SoloMerge)
///
/// # UNSOUND merge (W8 / SoloMerge)
///
/// `merge` never asserts that a second token covenant is an input of the
/// spending transaction. `hash256(all_prevouts) === extract_hash_prevouts(preimage)`
/// only proves `all_prevouts` is the real prevout list. A one-input spend takes
/// the "I am input 0" arm and writes the spender-chosen `other_balance` into
/// the successor. A P2PKH fee input filling `len(all_prevouts) == 72` does not
/// close the hole. Pin:
/// `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
/// For a construction that binds a specific companion input, see
/// `examples/ts/companion-verifier/`.
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
            self.add_output(output_satoshis, self.owner.clone(), total_balance - amount, 0);
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
    pub fn send(&mut self, sig: &Sig, to: PubKey, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(output_satoshis >= 1);
        self.add_output(output_satoshis, to, self.balance + self.merge_balance, 0);
    }

    /// Merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
    ///
    /// # UNSOUND (W8 / SoloMerge)
    ///
    /// This method does not authenticate a second token input. The
    /// position-dependent slot construction below is the intended two-input
    /// argument; its premise (a second input running this covenant) is never
    /// checked. A one-input spend writes `other_balance` into the successor.
    /// Pin:
    /// `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
    ///
    /// What the script actually does, if two token inputs happen to be present:
    /// each input writes its own locking-script balance to a slot based on
    /// whether its outpoint is first in `all_prevouts`, and `hash_outputs` then
    /// forces those two inputs to agree. That is not a proof that a second
    /// token input exists.
    ///
    /// # Parameters
    /// - `sig` - Current owner's signature (authorization)
    /// - `other_balance` - Claimed balance of the other merging input
    /// - `all_prevouts` - Concatenated outpoints of all tx inputs (verified via hash_prevouts)
    /// - `output_satoshis` - Satoshis to fund the merged output UTXO
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

        if my_outpoint == first_outpoint {
            // I'm input 0: my verified balance goes to slot 0
            self.add_output(output_satoshis, self.owner.clone(), my_balance, other_balance);
        } else {
            // I'm input 1: my verified balance goes to slot 1
            self.add_output(output_satoshis, self.owner.clone(), other_balance, my_balance);
        }
    }
}
