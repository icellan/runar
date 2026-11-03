import { SmartContract, assert, checkSig, hash160 } from 'runar-lang';
import type { Addr, ByteString, PubKey, Sig } from 'runar-lang';

/**
 * Directives — the two comment directives the compiler reads, in one contract.
 *
 * Both are real features with real on-chain consequences, and before R-209
 * neither had a single example anywhere in the repo: no `examples/`, no
 * conformance fixture, no mention in `docs/`. They were discoverable only by
 * reading the compiler's own tests.
 *
 * The COMMENT spelling below is `.runar.ts` only. The other eight surfaces
 * spell both directives natively instead (N-093) — e.g. a Go struct tag
 * option, a Rust attribute, a Java annotation; see the ports beside this file
 * in `examples/<format>/compiler-directives/` and `docs/formats/` — and their
 * parsers reject a COMMENT directive rather than silently ignoring it, because
 * ignoring one would change signing or DCE semantics without saying so.
 *
 * ---------------------------------------------------------------------------
 * `@embedAlways` — keep a readonly field the body never reads
 * ---------------------------------------------------------------------------
 * A readonly property that no method references is eliminated: its `load_prop`
 * is dead, so no constructor slot is emitted and the value never reaches the
 * locking script. That is usually right, and wrong for deploy-time metadata an
 * author intends to recover from the script later. `@embedAlways` opts the
 * field out of that elimination; without it the compiler emits a warning
 * naming the directive.
 *
 * The effect is visible in the artifact's `constructorSlots` — the byte offsets
 * the deploy-time values are spliced into — and NOT in `abi.constructor.params`,
 * which lists the declared signature and keeps the parameter either way. With
 * the directive the slots are [deployTag, pubKeyHash, pubKeyHash]; without it,
 * [pubKeyHash, pubKeyHash], and the value never reaches the locking script even
 * though the constructor still takes it.
 *
 * ---------------------------------------------------------------------------
 * `@sighash` — declare what the covenant commits to
 * ---------------------------------------------------------------------------
 * A public method's auto-injected covenant (and the preimage the SDK builds for
 * it) commits to `ALL|FORKID` by default. `@sighash` declares a different
 * BIP-143 mode. `SINGLE|FORKID` commits to only the output at the same index as
 * the input being signed, which is what lets one party fix their own output and
 * leave the rest of the transaction open for someone else to complete.
 *
 * Exactly one base type (`ALL`, `NONE`, `SINGLE`) must appear; `FORKID` and
 * `ANYONECANPAY` are modifiers.
 */
export class Directives extends SmartContract {
  readonly pubKeyHash: Addr;

  /** @embedAlways */
  readonly deployTag: ByteString;

  constructor(pubKeyHash: Addr, deployTag: ByteString) {
    super(pubKeyHash, deployTag);
    this.pubKeyHash = pubKeyHash;
    this.deployTag = deployTag;
  }

  /** Default mode: no directive, so the covenant commits to ALL|FORKID. */
  public spendAll(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }

  /** @sighash SINGLE|FORKID */
  public spendSingle(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
