import { StatefulSmartContract, ByteString, assert, len, extractPrevOutputScript } from 'runar-lang';

/**
 * IntentPrevOutputScript exercises the `extractPrevOutputScript` intent
 * intrinsic. The intrinsic asserts that a caller-supplied byte string hashes
 * to `expectedHash` and returns it; this contract then asserts the string is
 * non-empty.
 *
 * It does NOT read input 0 (W6 / GhostInput). The first argument is a
 * compile-time label naming the auto-injected witness parameter
 * `_prevOutScript_0`, which the unlocking script supplies. There is no vin
 * lookup, no parent transaction and no input-count check in the emitted
 * script. For a construction that binds a specific companion INPUT, see
 * `examples/ts/companion-verifier/`.
 */
class IntentPrevOutputScript extends StatefulSmartContract {
  readonly expectedHash: ByteString;
  count: bigint;

  constructor(expectedHash: ByteString, count: bigint) {
    super(expectedHash, count);
    this.expectedHash = expectedHash;
    this.count = count;
  }

  public bind() {
    const s = extractPrevOutputScript(0n, this.expectedHash);
    assert(len(s) > 0n);
    this.count = this.count + 1n;
  }
}
