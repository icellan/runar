import { StatefulSmartContract, sha256Finalize } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * Sha256FinalizeProbe -- source for `sha256-finalize-probe.anf.json` (D11).
 *
 * `sha256Finalize` was modelled by the TS testing interpreter and the native
 * runtimes, but five SDK ANF interpreters (Go, Python, Ruby, Rust, Zig) fell
 * through to "unknown builtin" and returned nil / None / undefined, and the
 * TS SDK and Java refused it. Any state field derived from it was therefore
 * silently wrong (or the call refused) off-chain.
 *
 * Routing the digest into a STATE field makes it part of the lenient
 * envelope every driver must reproduce, and lets the script-semantics oracle
 * compare it against the compiled script running on the real Spend engine.
 * The method has no assert: the state continuation the compiler appends is
 * what commits the digest on chain.
 */
class Sha256FinalizeProbe extends StatefulSmartContract {
  digest: ByteString;

  constructor(digest: ByteString) {
    super(digest);
    this.digest = digest;
  }

  public finalize(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
    this.digest = sha256Finalize(state, remaining, msgBitLen);
  }
}
