import {
  StatefulSmartContract, assert, checkSig, hash256, substr, len, cat, bin2num,
  extractHashPrevouts, extractOutpoint, extractOutputHash,
} from 'runar-lang';
import type { PubKey, Sig, ByteString, Sha256 } from 'runar-lang';

/**
 * CompanionVerifier -- the "Verified Companion Inputs" pattern: a Bitcoin
 * Script covenant that verifies ATTRIBUTES of a companion input by parsing
 * that input's parent transaction, bound to the spending transaction via the
 * BIP-143 preimage. No oracle, no indexer, no coordinator.
 *
 * This demonstrates cross-contract composition one step beyond
 * `examples/ts/cross-covenant/` (which verifies externally supplied output
 * data against a known script hash): here the external data is a FULL parent
 * transaction, cryptographically bound to a real input of THIS spend, and
 * the companion's contract identity is proven by template hash rather than
 * exact script hash -- so the check survives per-instance attribute values.
 *
 * The normative steps (each numbered in the method body):
 *  1. PREVOUTS BINDING -- `allPrevouts` (unlock data) is bound to THIS tx:
 *     hash256(allPrevouts) === hashPrevouts(preimage).
 *  2. POSITIONAL CONVENTION -- this covenant is input 0; the companion is
 *     input 1; the companion UTXO is output 0 of its parent tx.
 *  3. PARENT BINDING -- the supplied parent tx is bound by hash:
 *     hash256(parentTx) === txid in the companion's outpoint. Outpoint txids
 *     are in INTERNAL byte order -- the same order hash256 produces -- so the
 *     comparison is like-for-like, NO byte reversal (the classic footgun).
 *  4. STRUCTURAL WALK -- deterministic parse of the parent's bytes (bounded
 *     multi-input skip, 1..3 inputs) to output 0's locking script.
 *  5. TEMPLATE IDENTITY -- hash256 of that script with the attribute slots
 *     EXCISED must equal the known template hash. This proves the companion
 *     IS an instance of the expected contract and defeats attribute-planting
 *     counterfeits.
 *  6. ATTRIBUTE EXTRACTION + PREDICATE -- substr the fixed-width slots; apply
 *     the predicate (here: allowlist membership + category equality + state
 *     threshold; any predicate over the extracted bytes works).
 *  7. OUTPUT BINDING -- hash256(expectedOutputs) === hashOutputs(preimage), so
 *     ALL covenants in the tx agree on one output set (terminal form).
 *
 * SECURITY NOTE on excised slots: the template hash is a SHAPE commitment.
 * Every excised slot is attacker-controlled bytes until the covenant
 * value-checks it -- which is why step 6 checks BOTH slots (allowlist for
 * the attestor, exact OP_N compare for the category). Never excise a slot
 * you do not also value-check.
 *
 * SIGN-BYTE DISCIPLINE: every bin2num on parsed bytes is padded with a
 * trailing zero byte (`cat(bytes, PAD00)`) so values whose top bit is set can
 * never read negative. This is the bug class the pattern must codify.
 *
 * The baked layout constants (attestorOffset / categoryOffset / codePostLen /
 * expectedTemplateHash) come from the companion artifact's verification
 * descriptors: `resolveSlotLayout` + `computeTemplateHash` in runar-sdk.
 * See the test file for the derivation.
 */
class CompanionVerifier extends StatefulSmartContract {
  /** Operator of this verifier. Mutable state. */
  owner: PubKey;
  /** Count of companions verified. Mutable state. */
  companionsVerified: bigint;

  /** Byte offset of attribute slot #1 (33-byte attestor pubkey) inside the
   *  companion's locking script (from its constructorSlots). */
  readonly attestorOffset: bigint;
  /** Byte offset of attribute slot #2 (single OP_N category opcode; the enum
   *  is constrained to 1..16 so the slot is always exactly 1 byte). Must be
   *  > attestorOffset + 33. */
  readonly categoryOffset: bigint;
  /** Length of the companion code part AFTER the category slot ends
   *  (codeLen - categoryOffset - 1). */
  readonly codePostLen: bigint;
  /** hash256 of the companion code part with BOTH attribute slots excised
   *  (33-byte attestor + 1-byte category) -- the template identity. */
  readonly expectedTemplateHash: Sha256;
  /** Attribute predicate data: approved attestors (allowlist of 2). */
  readonly allowedAttestor1: PubKey;
  readonly allowedAttestor2: PubKey;
  /** Attribute predicate data: minimum companion amount accepted. */
  readonly minAmount: bigint;
  /** Attribute predicate data: required category enum value (1..16). The
   *  companion's baked opcode must equal OP_N for this N (byte = 0x50 + N). */
  readonly requiredCategory: bigint;

  /** Zero pad for sign-safe bin2num on parsed little-endian fields. */
  readonly pad00: ByteString = "00" as ByteString;

  constructor(
    owner: PubKey,
    companionsVerified: bigint,
    attestorOffset: bigint,
    categoryOffset: bigint,
    codePostLen: bigint,
    expectedTemplateHash: Sha256,
    allowedAttestor1: PubKey,
    allowedAttestor2: PubKey,
    minAmount: bigint,
    requiredCategory: bigint,
  ) {
    super(owner, companionsVerified, attestorOffset, categoryOffset, codePostLen, expectedTemplateHash, allowedAttestor1, allowedAttestor2, minAmount, requiredCategory);
    this.owner = owner;
    this.companionsVerified = companionsVerified;
    this.attestorOffset = attestorOffset;
    this.categoryOffset = categoryOffset;
    this.codePostLen = codePostLen;
    this.expectedTemplateHash = expectedTemplateHash;
    this.allowedAttestor1 = allowedAttestor1;
    this.allowedAttestor2 = allowedAttestor2;
    this.minAmount = minAmount;
    this.requiredCategory = requiredCategory;
  }

  /**
   * Verify the companion input (input 1) against this verifier's attribute
   * predicate, by parsing the companion's parent transaction in Script.
   *
   * TERMINAL method: this UTXO is fully spent; no continuation. The spending
   * tx's outputs are bound via extractOutputHash, and the companion input's
   * own covenant (e.g. AttributedToken.retire) independently enforces ITS
   * continuation -- so both covenant inputs agree on the same output set.
   *
   * @param sig               - owner's signature
   * @param allPrevouts       - concatenated 36-byte outpoints of ALL inputs of THIS tx
   * @param companionParentTx - full serialized parent transaction of the companion input
   * @param expectedOutputs   - serialized outputs of THIS tx (value8|varint|script per output)
   */
  public verifyCompanion(sig: Sig, allPrevouts: ByteString, companionParentTx: ByteString, expectedOutputs: ByteString) {
    assert(checkSig(sig, this.owner));

    // -- 1. Bind allPrevouts to the real spending tx. --
    assert(hash256(allPrevouts) === extractHashPrevouts(this.txPreimage));
    assert(len(allPrevouts) >= 72n); // at least: this input + the companion input

    // -- 2. Positional convention: I am input 0; the companion is input 1. --
    const myOutpoint = extractOutpoint(this.txPreimage);
    assert(substr(allPrevouts, 0n, 36n) === myOutpoint);
    const companionOutpoint = substr(allPrevouts, 36n, 36n);
    const companionTxid = substr(companionOutpoint, 0n, 32n);
    // vout must be 0 (sign-safe read of 4-byte LE)
    const companionVout = bin2num(cat(substr(companionOutpoint, 32n, 4n), this.pad00));
    assert(companionVout === 0n);

    // -- 3. Bind the supplied parent tx by hash. Internal byte order both sides; no reversal. --
    assert(hash256(companionParentTx) === companionTxid);

    // -- 4. Walk to output 0's locking script. --
    // version(4) | inCount(varint) | inputs... | outCount(varint) | outputs... | locktime(4)
    // Bounded multi-input walk (1..3 inputs -- the general profile). inCount is
    // a 1-byte varint by construction: >3 rejects, and a 0xfd/0xfe/0xff marker
    // byte reads as 253/254/255 which also rejects.
    const inCount = bin2num(cat(substr(companionParentTx, 4n, 1n), this.pad00));
    assert(inCount >= 1n);
    assert(inCount <= 3n);
    // each input: outpoint(36) + scriptLen varint (1-byte only, sign-safe;
    // P2PKH unlock ~107B) + script + sequence(4)
    let off = 5n;
    for (let i = 0n; i < 3n; i++) {
      if (i < inCount) {
        const sl = bin2num(cat(substr(companionParentTx, off + 36n, 1n), this.pad00));
        assert(sl < 253n);
        off = off + 36n + 1n + sl + 4n;
      }
    }
    // outputs section starts at off
    const outCountPrefix = bin2num(cat(substr(companionParentTx, off, 1n), this.pad00));
    assert(outCountPrefix !== 254n);
    assert(outCountPrefix !== 255n);
    let outHdr = 1n;
    let outCount = outCountPrefix;
    if (outCountPrefix === 253n) {
      outCount = bin2num(cat(substr(companionParentTx, off + 1n, 2n), this.pad00));
      outHdr = 3n;
    }
    assert(outCount >= 1n);
    // output 0 = value(8) + scriptLen(varint) + script. Companion scripts are
    // >252B -> the varint MUST be 0xfd + LE16 (also rejects short scripts like P2PKH).
    const marker = bin2num(cat(substr(companionParentTx, off + outHdr + 8n, 1n), this.pad00));
    assert(marker === 253n);
    const scriptLen = bin2num(cat(substr(companionParentTx, off + outHdr + 9n, 2n), this.pad00));
    const scriptStart = off + outHdr + 11n;
    assert(len(companionParentTx) >= scriptStart + scriptLen);
    const companionScript = substr(companionParentTx, scriptStart, scriptLen);

    // -- 5. Template identity: the companion IS an instance of the expected
    //       contract. BOTH attribute slots are excised (33-byte attestor +
    //       1-byte category opcode), leaving a fixed-layout template.
    const codePre = substr(companionScript, 0n, this.attestorOffset);
    const codeMid = substr(companionScript, this.attestorOffset + 33n, this.categoryOffset - this.attestorOffset - 33n);
    const codePost = substr(companionScript, this.categoryOffset + 1n, this.codePostLen);
    assert(hash256(cat(cat(codePre, codeMid), codePost)) === this.expectedTemplateHash);

    // -- 6. Attribute extraction + predicate. --
    // 6a. Attestor allowlist membership (the worked predicate).
    const attestor = substr(companionScript, this.attestorOffset, 33n);
    assert(attestor === this.allowedAttestor1 || attestor === this.allowedAttestor2);

    // 6b. Category enum: the baked slot is the single opcode OP_N (byte
    //     0x50 + N). Read the raw opcode byte sign-safely and require it to
    //     encode exactly requiredCategory (1..16). NOTE: this slot is excised
    //     from the template, so WITHOUT this check an attacker could plant
    //     any byte here -- the sign-safe read also defeats bytes >= 0x80.
    const catOp = bin2num(cat(substr(companionScript, this.categoryOffset, 1n), this.pad00));
    assert(catOp === this.requiredCategory + 80n);

    // 6c. Predicates over the companion's STATE region (fixed 8-byte LE
    //     fields at the script tail: [.. owner(33) | amount(8) | status(8)]).
    //     Sign-safe reads: an 8-byte LE value with its top bit set (e.g.
    //     2^63) would read NEGATIVE unpadded -- the pad00 cat prevents it.
    const companionAmount = bin2num(cat(substr(companionScript, scriptLen - 16n, 8n), this.pad00));
    const companionStatus = bin2num(cat(substr(companionScript, scriptLen - 8n, 8n), this.pad00));
    assert(companionStatus === 1n); // must be Active (not Retired/Revoked)
    assert(companionAmount >= this.minAmount);

    // -- 7. Terminal output binding: the spending tx's outputs are exactly the supplied set. --
    assert(hash256(expectedOutputs) === extractOutputHash(this.txPreimage));
  }
}
