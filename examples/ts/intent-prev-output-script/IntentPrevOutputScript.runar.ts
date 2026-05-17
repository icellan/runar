import { StatefulSmartContract, ByteString, assert, len, extractPrevOutputScript } from 'runar-lang';

/**
 * IntentPrevOutputScript exercises the `extractPrevOutputScript`
 * intent intrinsic. The contract reads input 0's previous-output
 * locking script via the witness-bridge pattern and asserts it is
 * non-empty after the hash-equality check the intrinsic emits
 * internally.
 *
 * The auto-injected method parameter `_prevOutScript_0` is supplied
 * by the unlocking script and verified against `expectedHash` inside
 * the intrinsic.
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
