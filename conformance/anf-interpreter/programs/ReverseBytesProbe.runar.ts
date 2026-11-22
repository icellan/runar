import { StatefulSmartContract, reverseBytes } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * ReverseBytesProbe -- source for `reverse-bytes-probe.anf.json`.
 *
 * Since D12 BM-F3 (PR #228) every compiler's reverseBytes ends in
 * `OP_0 OP_EQUALVERIFY`, so the deployed script ABORTS on an input longer
 * than 520 bytes. Routing the result into a STATE field puts it in the
 * lenient envelope every SDK driver must reproduce (0 / 1 / 520 bytes,
 * inputs/reverse-bytes-*.json) and lets the script-semantics oracle compare
 * it against the compiled script. The 521-byte refusal is pinned per tier by
 * ../reverse-bytes-bound.test.ts.
 */
class ReverseBytesProbe extends StatefulSmartContract {
  out: ByteString;

  constructor(out: ByteString) {
    super(out);
    this.out = out;
  }

  public reverse(data: ByteString) {
    this.out = reverseBytes(data);
  }
}
