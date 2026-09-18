import {
  StatefulSmartContract, assert, checkSig, hash256, substr, len, cat, bin2num, num2bin,
  extractHashPrevouts, extractOutpoint, extractScriptCode,
} from 'runar-lang';
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
 * - `merge`    -- Merge: 2 UTXOs -> 1 UTXO. Authenticates the companion via its parent tx.
 *
 * **Companion-parent merge (W8 / SoloMerge):** `hash256(allPrevouts) ===
 * extractHashPrevouts(preimage)` only proves `allPrevouts` is the real prevout
 * list. Input count is not identity. `merge` therefore binds a specific
 * companion outpoint (I am the first or second of the first two prevouts),
 * requires that companion to be output 0 of `otherParentTx`, walks that
 * parent to its output-0 locking script, checks the code prefix against
 * this input's `extractScriptCode` (so a P2PKH fee input cannot fill the
 * slot), and reads the companion's state-tail balances. Pin:
 * `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
 * Walk profile matches `examples/ts/companion-verifier/`.
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
   * Merge: 2 UTXOs -> 1 UTXO. Consolidates two token UTXOs.
   *
   * Authenticates the companion by parsing `otherParentTx` (the parent of
   * the other merging input). I must be the first or second 36-byte
   * outpoint in `allPrevouts`; the other of those two is the companion,
   * which must be vout 0 of a parent whose output-0 script is this same
   * token (code prefix `len-49`) and whose state-tail balances sum to
   * `otherBalance`. A one-input spend and a token+P2PKH spend both fail
   * that walk. Pin:
   * `packages/runar-testing/src/__tests__/w8-token-ft-solo-merge-known-broken.test.ts`.
   *
   * Each of the two token inputs then writes its own locking-script
   * balance to a slot based on whether its outpoint is first in
   * `allPrevouts`; `hashOutputs` forces those two writes to agree.
   *
   * @param sig            - Current owner's signature
   * @param otherBalance   - Claimed total balance of the companion input
   * @param allPrevouts    - Concatenated outpoints of all tx inputs (verified via hashPrevouts)
   * @param otherParentTx  - Full serialized parent transaction of the companion input
   * @param outputSatoshis - Satoshis to fund the merged output
   */
  public merge(sig: Sig, otherBalance: bigint, allPrevouts: ByteString, otherParentTx: ByteString, outputSatoshis: bigint) {
    assert(checkSig(sig, this.owner));
    assert(outputSatoshis >= 1n);
    assert(otherBalance >= 0n);
    assert(len(this.tokenId) > 0n);

    const pad00 = num2bin(0n, 1n);

    // 1. Bind allPrevouts to this tx. Input count is not identity.
    assert(hash256(allPrevouts) === extractHashPrevouts(this.txPreimage));
    assert(len(allPrevouts) >= 72n);

    // 2. I am first or second of the first two prevouts; the other is the companion.
    const myOutpoint = extractOutpoint(this.txPreimage);
    const firstOutpoint = substr(allPrevouts, 0n, 36n);
    const secondOutpoint = substr(allPrevouts, 36n, 36n);
    let companionOutpoint: ByteString = firstOutpoint;
    if (myOutpoint === firstOutpoint) {
      companionOutpoint = secondOutpoint;
    } else {
      assert(myOutpoint === secondOutpoint);
    }
    const companionTxid = substr(companionOutpoint, 0n, 32n);
    const companionVout = bin2num(cat(substr(companionOutpoint, 32n, 4n), pad00));
    assert(companionVout === 0n);

    // 3. Bind the supplied parent. Internal byte order both sides; no reversal.
    assert(hash256(otherParentTx) === companionTxid);

    // 4. Walk to output 0's locking script. Same 1..3 input profile as companion-verifier.
    const inCount = bin2num(cat(substr(otherParentTx, 4n, 1n), pad00));
    assert(inCount >= 1n);
    assert(inCount <= 3n);
    let off = 5n;
    if (0n < inCount) {
      const sl = bin2num(cat(substr(otherParentTx, off + 36n, 1n), pad00));
      assert(sl < 253n);
      off = off + 36n + 1n + sl + 4n;
    }
    if (1n < inCount) {
      const sl = bin2num(cat(substr(otherParentTx, off + 36n, 1n), pad00));
      assert(sl < 253n);
      off = off + 36n + 1n + sl + 4n;
    }
    if (2n < inCount) {
      const sl = bin2num(cat(substr(otherParentTx, off + 36n, 1n), pad00));
      assert(sl < 253n);
      off = off + 36n + 1n + sl + 4n;
    }
    const outCountMarker = bin2num(cat(substr(otherParentTx, off, 1n), pad00));
    let outCount = outCountMarker;
    let outCountSize = 1n;
    if (outCountMarker === 253n) {
      outCount = bin2num(cat(substr(otherParentTx, off + 1n, 2n), pad00));
      assert(outCount >= 253n);
      outCountSize = 3n;
    }
    if (outCountMarker === 254n) {
      outCount = bin2num(cat(substr(otherParentTx, off + 1n, 4n), pad00));
      assert(outCount > 65535n);
      outCountSize = 5n;
    }
    if (outCountMarker === 255n) {
      outCount = bin2num(cat(substr(otherParentTx, off + 1n, 8n), pad00));
      assert(outCount > 4294967295n);
      outCountSize = 9n;
    }
    assert(outCount >= 1n);
    off = off + outCountSize;
    // Token locking scripts are >252 B, so the varint MUST be 0xfd + LE16
    // (also rejects a P2PKH fee input sitting in the companion slot).
    const marker = bin2num(cat(substr(otherParentTx, off + 8n, 1n), pad00));
    assert(marker === 253n);
    const scriptLen = bin2num(cat(substr(otherParentTx, off + 9n, 2n), pad00));
    const scriptStart = off + 11n;
    assert(len(otherParentTx) >= scriptStart + scriptLen);
    const companionScript = substr(otherParentTx, scriptStart, scriptLen);
    assert(scriptLen > 49n);

    // 5. Identity: companion code+OP_RETURN equals this input's scriptCode
    //    after dropping the BIP-143 CompactSize prefix (0xfd + LE16 for this
    //    contract) and the 2-byte OP_NOP OP_CODESEPARATOR prologue, excluding
    //    the 49-byte state tail (owner || balance || mergeBalance).
    const sc = extractScriptCode(this.txPreimage);
    const scMarker = bin2num(cat(substr(sc, 0n, 1n), pad00));
    assert(scMarker === 253n);
    const myBody = substr(sc, 3n, len(sc) - 3n);
    const companionBody = substr(companionScript, 2n, scriptLen - 2n);
    assert(len(myBody) === len(companionBody));
    assert(len(myBody) > 49n);
    assert(substr(myBody, 0n, len(myBody) - 49n) === substr(companionBody, 0n, len(companionBody) - 49n));

    // 6. Companion total balance is the state-tail sum, not the spender's number.
    const otherPrimary = bin2num(cat(substr(companionScript, scriptLen - 16n, 8n), pad00));
    const otherMerge = bin2num(cat(substr(companionScript, scriptLen - 8n, 8n), pad00));
    assert(otherPrimary + otherMerge === otherBalance);

    const myBalance = this.balance + this.mergeBalance;
    if (myOutpoint === firstOutpoint) {
      this.addOutput(outputSatoshis, this.owner, myBalance, otherBalance);
    } else {
      this.addOutput(outputSatoshis, this.owner, otherBalance, myBalance);
    }
  }
}
