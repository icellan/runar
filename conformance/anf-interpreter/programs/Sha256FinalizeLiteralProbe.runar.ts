import { StatefulSmartContract, sha256Finalize } from 'runar-lang';
import type { ByteString } from 'runar-lang';

/**
 * Sha256FinalizeLiteralProbe -- source for `sha256-finalize-literal-probe.anf.json`
 * (D11). The same probe as Sha256FinalizeProbe, but msgBitLen is a LITERAL, so
 * it reaches each interpreter as a `load_const` whose checked-in JSON value is
 * a bare number, not a method argument. The TS SDK interpreter refused that
 * shape ("msgBitLen must be a bigint") when only the parameter form was tested.
 */
class Sha256FinalizeLiteralProbe extends StatefulSmartContract {
  digest: ByteString;

  constructor(digest: ByteString) {
    super(digest);
    this.digest = digest;
  }

  public finalize(state: ByteString, remaining: ByteString) {
    this.digest = sha256Finalize(state, remaining, 24n);
  }
}
