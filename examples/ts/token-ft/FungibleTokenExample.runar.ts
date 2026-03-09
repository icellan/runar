import { StatefulSmartContract, assert, checkSig, hash256, substr, extractHashPrevouts, extractOutpoint } from 'runar-lang';
import type { PubKey, Sig, ByteString } from 'runar-lang';

/**
 * FungibleToken -- A UTXO-based fungible token using Runar's multi-output (`addOutput`) facility.
 *
 * Demonstrates how to model divisible token balances that can be split, transferred, and
 * merged -- similar to colored coins or SLP-style tokens but enforced entirely by Bitcoin Script.
 *
 * **UTXO token model vs account model:**
 * Unlike Ethereum ERC-20 where balances live in a global mapping, each token "balance" here
 * is a separate UTXO. The UTXO carries state: the current owner (PubKey), balance (bigint),
 * and an immutable tokenId (ByteString). Transferring tokens means spending one UTXO and
 * creating new ones with updated state.
 *
 * **Operations:**
 * - `transfer` -- Split: 1 UTXO -> 2 UTXOs (recipient + change back to sender)
 * - `send`     -- Simple send: 1 UTXO -> 1 UTXO (full balance to new owner)
 * - `merge`    -- Secure merge: 2 UTXOs -> 1 UTXO (consolidate two token UTXOs)
 *
 * **Secure merge design:**
 * The merge uses position-dependent output construction verified via `hashPrevouts`.
 * Each input reads its own balance from its locking script (verified by OP_PUSH_TX)
 * and writes it to a specific slot in the output based on its position in the transaction.
 * Since `hashOutputs` forces both inputs to agree on the exact same output, each input's
 * claimed `otherBalance` must equal the other input's real verified balance.
 * This prevents the inflation attack where an attacker lies about `otherBalance`.
 *
 * The output stores both individual balances (`balance` and `mergeBalance`) so they can
 * be independently verified. Subsequent operations use the sum as the available balance.
 *
 * **Authorization:** All operations require the current owner's ECDSA signature via `checkSig`.
 */
class FungibleToken extends StatefulSmartContract {
  /** Current owner's public key. Mutable -- updated when tokens are sent to a new owner. */
  owner: PubKey;
  /** Primary token balance. Mutable -- adjusted on transfer/split/merge. */
  balance: bigint;
  /** Secondary balance slot used during merge for cross-input verification. Normally 0. */
  mergeBalance: bigint;
  /**
   * Unique token identifier. Readonly -- baked into the locking script at deploy time
   * and cannot change, ensuring token identity is preserved across all transfers.
   */
  readonly tokenId: ByteString;

  constructor(owner: PubKey, balance: bigint, mergeBalance: bigint, tokenId: ByteString) {
    super(owner, balance, mergeBalance, tokenId);
    this.owner = owner;
    this.balance = balance;
    this.mergeBalance = mergeBalance;
    this.tokenId = tokenId;
  }

  /**
   * Transfer tokens to a recipient. If the full balance is sent, produces 1 output;
   * otherwise produces 2 outputs (recipient + change back to sender).
   */
  public transfer(sig: Sig, to: PubKey, amount: bigint, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    const totalBalance = this.balance + this.mergeBalance;
    assert(amount > 0n);
    assert(amount <= totalBalance);

    this.addOutput(outputSatoshis, to, amount, 0n);
    if (amount < totalBalance) {
      this.addOutput(outputSatoshis, this.owner, totalBalance - amount, 0n);
    }
  }

  /**
   * Simple send: 1 UTXO -> 1 UTXO. Transfers the entire balance to a new owner.
   */
  public send(sig: Sig, to: PubKey, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);

    this.addOutput(outputSatoshis, to, this.balance + this.mergeBalance, 0n);
  }

  /**
   * Secure merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
   *
   * **Why this is secure (anti-inflation proof):**
   *
   * Each input reads its own balance from its locking script (`this.balance`), which is
   * verified by OP_PUSH_TX — it cannot be faked. Each input writes its verified balance
   * to a specific output slot based on its position in the transaction.
   *
   * Position is derived from `allPrevouts` (verified against `hashPrevouts` in the
   * preimage, so it reflects the real transaction) and the input's own outpoint.
   *
   * The output has two balance slots: `balance` (slot 0) and `mergeBalance` (slot 1).
   * Each input places its own verified balance in its slot, and the claimed `otherBalance`
   * in the other slot:
   *
   *   Input 0 (balance=400): addOutput(sats, owner, 400, otherBalance₀)
   *   Input 1 (balance=600): addOutput(sats, owner, otherBalance₁, 600)
   *
   * Both inputs must produce byte-identical outputs (enforced by `hashOutputs` in BIP-143).
   * This forces:
   *   - slot 0: 400 == otherBalance₁  →  input 1 MUST pass 400
   *   - slot 1: otherBalance₀ == 600  →  input 0 MUST pass 600
   *
   * Any lie causes a `hashOutputs` mismatch and the transaction is rejected on-chain.
   * The inputs can be in any order — each self-discovers its position from the preimage.
   *
   * @param sig            - Current owner's signature
   * @param otherBalance   - Claimed balance of the other merging input
   * @param allPrevouts    - Concatenated outpoints of all tx inputs (verified via hashPrevouts)
   * @param outputSatoshis - Satoshis to fund the merged output
   */
  public merge(sig: Sig, otherBalance: bigint, allPrevouts: ByteString, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    assert(otherBalance >= 0n);

    // Verify allPrevouts is authentic (matches the actual transaction inputs)
    assert(hash256(allPrevouts) === extractHashPrevouts(this.txPreimage));

    // Determine position: am I the first contract input?
    const myOutpoint = extractOutpoint(this.txPreimage);
    const firstOutpoint = substr(allPrevouts, 0n, 36n);
    const myBalance = this.balance + this.mergeBalance;

    if (myOutpoint === firstOutpoint) {
      // I'm input 0: my verified balance goes to slot 0
      this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
    } else {
      // I'm input 1: my verified balance goes to slot 1
      this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
    }
  }
}
