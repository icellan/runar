// EXCLUDED FROM NATIVE RUST COMPILATION
//
// `cargo test` does not `#[path]`-include this file. FungibleToken_test.rs
// keeps an inline duplicate because native tests need recorded `add_output`
// results (`outputs.len()`, per-output balances). The runar-rs-macros
// contract proc-macro now generates `add_output`, but that impl discards the arguments
// (`let _ = field`) so a `#[path]` include would compile and then make every
// transfer/send assertion vacuous.
//
// W8 merge also walks a real companion parent (`hash256(other_parent_tx)`,
// `extract_outpoint`, `extract_script_code`, CompactSize 0xfd+LE16). Native
// mocks return empty scriptCode and zero outpoints, so that walk cannot be
// exercised as Rust without a Spend-level parent. That pin lives in
// `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
// `test_compile` still runs `runar::compile_check` on this file.
//
// Pinned by `examples/rust/native-exclusions/exclusions_test.rs`. Remove this
// header and the entry there in the same commit that wires a recording
// `add_output` surface and a native W8 parent walk.

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
/// - `merge`    -- Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).
///
/// # Companion-parent merge (W8 / SoloMerge)
///
/// Authenticates the companion via `other_parent_tx`. Input count is not
/// identity. Pin:
/// `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
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

    /// Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).
    pub fn merge(&mut self, sig: &Sig, other_balance: Bigint, all_prevouts: ByteString, other_parent_tx: ByteString, output_satoshis: Bigint) {
        assert!(check_sig(sig, &self.owner));
        assert!(output_satoshis >= 1);
        assert!(other_balance >= 0);
        assert!(len(&self.token_id) > 0);

        let pad00 = num2bin(0, 1);
        assert!(hash256(&all_prevouts) == extract_hash_prevouts(&self.tx_preimage));
        assert!(len(&all_prevouts) >= 72);

        let my_outpoint = extract_outpoint(&self.tx_preimage);
        let first_outpoint = substr(&all_prevouts, 0, 36);
        let second_outpoint = substr(&all_prevouts, 36, 36);
        let mut companion_outpoint = first_outpoint.clone();
        if my_outpoint == first_outpoint {
            companion_outpoint = second_outpoint;
        } else {
            assert!(my_outpoint == second_outpoint);
        }
        let companion_txid = substr(&companion_outpoint, 0, 32);
        let companion_vout = bin2num(cat(substr(&companion_outpoint, 32, 4), pad00.clone()));
        assert!(companion_vout == 0);
        assert!(hash256(&other_parent_tx) == companion_txid);

        let in_count = bin2num(cat(substr(&other_parent_tx, 4, 1), pad00.clone()));
        assert!(in_count >= 1);
        assert!(in_count <= 3);
        let mut off: Bigint = 5;
        if 0 < in_count {
            let sl = bin2num(cat(substr(&other_parent_tx, off + 36, 1), pad00.clone()));
            assert!(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        if 1 < in_count {
            let sl = bin2num(cat(substr(&other_parent_tx, off + 36, 1), pad00.clone()));
            assert!(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        if 2 < in_count {
            let sl = bin2num(cat(substr(&other_parent_tx, off + 36, 1), pad00.clone()));
            assert!(sl < 253);
            off = off + 36 + 1 + sl + 4;
        }
        let out_count_marker = bin2num(cat(substr(&other_parent_tx, off, 1), pad00.clone()));
        let mut out_count = out_count_marker;
        let mut out_count_size: Bigint = 1;
        if out_count_marker == 253 {
            out_count = bin2num(cat(substr(&other_parent_tx, off + 1, 2), pad00.clone()));
            assert!(out_count >= 253);
            out_count_size = 3;
        }
        if out_count_marker == 254 {
            out_count = bin2num(cat(substr(&other_parent_tx, off + 1, 4), pad00.clone()));
            assert!(out_count > 65535);
            out_count_size = 5;
        }
        if out_count_marker == 255 {
            out_count = bin2num(cat(substr(&other_parent_tx, off + 1, 8), pad00.clone()));
            assert!(out_count > 4294967295);
            out_count_size = 9;
        }
        assert!(out_count >= 1);
        off = off + out_count_size;
        let marker = bin2num(cat(substr(&other_parent_tx, off + 8, 1), pad00.clone()));
        assert!(marker == 253);
        let script_len = bin2num(cat(substr(&other_parent_tx, off + 9, 2), pad00.clone()));
        let script_start = off + 11;
        assert!(len(&other_parent_tx) >= script_start + script_len);
        let companion_script = substr(&other_parent_tx, script_start, script_len);
        assert!(script_len > 49);

        let sc = extract_script_code(&self.tx_preimage);
        let sc_marker = bin2num(cat(substr(&sc, 0, 1), pad00.clone()));
        assert!(sc_marker == 253);
        let my_body = substr(&sc, 3, len(&sc) - 3);
        let companion_body = substr(&companion_script, 2, script_len - 2);
        assert!(len(&my_body) == len(&companion_body));
        assert!(len(&my_body) > 49);
        assert!(substr(&my_body, 0, len(&my_body) - 49) == substr(&companion_body, 0, len(&companion_body) - 49));

        let other_primary = bin2num(cat(substr(&companion_script, script_len - 16, 8), pad00.clone()));
        let other_merge = bin2num(cat(substr(&companion_script, script_len - 8, 8), pad00));
        assert!(other_primary + other_merge == other_balance);

        let my_balance = self.balance + self.merge_balance;
        if my_outpoint == first_outpoint {
            self.add_output(output_satoshis, self.owner.clone(), my_balance, other_balance);
        } else {
            self.add_output(output_satoshis, self.owner.clone(), other_balance, my_balance);
        }
    }
}
