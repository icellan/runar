from runar import (
    StatefulSmartContract, PubKey, Sig, ByteString, Bigint, Readonly,
    public, assert_, check_sig, hash256, substr, cat, bin2num, num2bin,
    extract_hash_prevouts, extract_outpoint, extract_script_code,
)


class FungibleToken(StatefulSmartContract):
    """A UTXO-based fungible token using Runar's multi-output (add_output) facility.

    Demonstrates how to model divisible token balances that can be split, transferred, and
    merged -- similar to colored coins or SLP-style tokens but enforced entirely by Bitcoin Script.

    UTXO token model vs account model:
        Unlike Ethereum ERC-20 where balances live in a global mapping, each token "balance"
        here is a separate UTXO. The UTXO carries state: the current owner (PubKey), balance
        (Bigint), and an immutable token_id (ByteString). Transferring tokens means spending
        one UTXO and creating new ones with updated state.

    Operations:
        transfer -- Split: 1 UTXO -> 2 UTXOs (recipient + change back to sender)
        send     -- Simple send: 1 UTXO -> 1 UTXO (full balance to new owner)
        merge    -- Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).

    Companion-parent merge (W8 / SoloMerge):
        authenticates the companion via other_parent_tx. Input count is not
        identity. Pin:
        packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.

        The output stores both individual balances (balance and merge_balance) so they
        can be independently verified. Subsequent operations use the sum as the
        available balance.

    Authorization:
        All operations require the current owner's ECDSA signature via check_sig.
    """

    owner: PubKey                    # Current owner's public key. Mutable -- updated on ownership transfer.
    balance: Bigint                  # Primary token balance. Mutable -- adjusted on transfer/split/merge.
    merge_balance: Bigint            # Secondary balance slot used during merge for cross-input verification. Normally 0.
    token_id: Readonly[ByteString]   # Unique token identifier. Readonly -- baked into the locking script, cannot change.

    def __init__(self, owner: PubKey, balance: Bigint, merge_balance: Bigint, token_id: ByteString):
        super().__init__(owner, balance, merge_balance, token_id)
        self.owner = owner
        self.balance = balance
        self.merge_balance = merge_balance
        self.token_id = token_id

    @public
    def transfer(self, sig: Sig, to: PubKey, amount: Bigint, output_satoshis: Bigint):
        """Transfer tokens to a recipient. If the full balance is sent, produces 1 output;
        otherwise produces 2 outputs (recipient + change back to sender).

        Uses add_output to create continuation UTXOs in the spending transaction.
        add_output(satoshis, ...state_values) takes positional state values matching mutable
        properties in declaration order: owner, balance, merge_balance.

        Args:
            sig: Current owner's signature (authorization).
            to: Recipient's public key.
            amount: Number of tokens to send (must be > 0 and <= total available balance).
            output_satoshis: Satoshis to fund each output UTXO.
        """
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        total_balance = self.balance + self.merge_balance
        assert_(amount > 0)
        assert_(amount <= total_balance)
        # First output: recipient receives `amount` tokens
        self.add_output(output_satoshis, to, amount, 0)
        # Second output: sender keeps the remaining balance as change (skip if fully spent)
        if amount < total_balance:
            self.add_output(output_satoshis, self.owner, total_balance - amount, 0)

    @public
    def send(self, sig: Sig, to: PubKey, output_satoshis: Bigint):
        """Simple send: 1 UTXO -> 1 UTXO. Transfers the entire balance to a new owner.

        Creates a single continuation UTXO with the same balance but a new owner.

        Args:
            sig: Current owner's signature (authorization).
            to: New owner's public key.
            output_satoshis: Satoshis to fund the output UTXO.
        """
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        self.add_output(output_satoshis, to, self.balance + self.merge_balance, 0)

    @public
    def merge(self, sig: Sig, other_balance: Bigint, all_prevouts: ByteString, other_parent_tx: ByteString, output_satoshis: Bigint):
        """Merge: 2 UTXOs -> 1 UTXO. Companion-parent merge (W8).

        Authenticates the companion via other_parent_tx. Pin:
        packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts.
        """
        assert_(check_sig(sig, self.owner))
        assert_(output_satoshis >= 1)
        assert_(other_balance >= 0)
        assert_(len(self.token_id) > 0)

        pad00 = num2bin(0, 1)
        assert_(hash256(all_prevouts) == extract_hash_prevouts(self.tx_preimage))
        assert_(len(all_prevouts) >= 72)

        my_outpoint = extract_outpoint(self.tx_preimage)
        first_outpoint = substr(all_prevouts, 0, 36)
        second_outpoint = substr(all_prevouts, 36, 36)
        companion_outpoint = first_outpoint
        if my_outpoint == first_outpoint:
            companion_outpoint = second_outpoint
        else:
            assert_(my_outpoint == second_outpoint)
        companion_txid = substr(companion_outpoint, 0, 32)
        companion_vout = bin2num(cat(substr(companion_outpoint, 32, 4), pad00))
        assert_(companion_vout == 0)
        assert_(hash256(other_parent_tx) == companion_txid)

        in_count = bin2num(cat(substr(other_parent_tx, 4, 1), pad00))
        assert_(in_count >= 1)
        assert_(in_count <= 3)
        off = 5
        if 0 < in_count:
            sl = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00))
            assert_(sl < 253)
            off = off + 36 + 1 + sl + 4
        if 1 < in_count:
            sl = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00))
            assert_(sl < 253)
            off = off + 36 + 1 + sl + 4
        if 2 < in_count:
            sl = bin2num(cat(substr(other_parent_tx, off + 36, 1), pad00))
            assert_(sl < 253)
            off = off + 36 + 1 + sl + 4
        out_count = bin2num(cat(substr(other_parent_tx, off, 1), pad00))
        assert_(out_count >= 1)
        marker = bin2num(cat(substr(other_parent_tx, off + 9, 1), pad00))
        assert_(marker == 253)
        script_len = bin2num(cat(substr(other_parent_tx, off + 10, 2), pad00))
        script_start = off + 12
        assert_(len(other_parent_tx) >= script_start + script_len)
        companion_script = substr(other_parent_tx, script_start, script_len)
        assert_(script_len > 49)

        sc = extract_script_code(self.tx_preimage)
        sc_marker = bin2num(cat(substr(sc, 0, 1), pad00))
        assert_(sc_marker == 253)
        my_body = substr(sc, 3, len(sc) - 3)
        companion_body = substr(companion_script, 2, script_len - 2)
        assert_(len(my_body) == len(companion_body))
        assert_(len(my_body) > 49)
        assert_(substr(my_body, 0, len(my_body) - 49) == substr(companion_body, 0, len(companion_body) - 49))

        other_primary = bin2num(cat(substr(companion_script, script_len - 16, 8), pad00))
        other_merge = bin2num(cat(substr(companion_script, script_len - 8, 8), pad00))
        assert_(other_primary + other_merge == other_balance)

        my_balance = self.balance + self.merge_balance
        if my_outpoint == first_outpoint:
            self.add_output(output_satoshis, self.owner, my_balance, other_balance)
        else:
            self.add_output(output_satoshis, self.owner, other_balance, my_balance)
