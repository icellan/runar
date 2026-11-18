import { StatefulSmartContract, sha256Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * Sha256CompressProbe -- source for `sha256-compress-probe.anf.json` (D16).
 *
 * `sha256Compress` was modelled by the TS testing interpreter and the native
 * runtimes, but no SDK ANF interpreter computed it: five (Go, Python, Ruby,
 * Rust, Zig) fell through to "unknown builtin" and returned nil / None /
 * undefined, and the TS SDK and Java refused it. Any state field derived from
 * it was therefore silently wrong (or the call refused) off-chain.
 *
 * Routing the compressed state into a STATE field makes it part of the
 * lenient envelope every driver must reproduce, and lets the script-semantics
 * oracle compare it against the compiled script running on the real Spend
 * engine. The method has no assert: the state continuation the compiler
 * appends is what commits the digest on chain.
 */
class Sha256CompressProbe extends StatefulSmartContract {
  digest: ByteString;

  constructor(digest: ByteString) {
    super(digest);
    this.digest = digest;
  }

  public compress(state: ByteString, block: ByteString) {
    this.digest = sha256Compress(state, block);
  }
}
