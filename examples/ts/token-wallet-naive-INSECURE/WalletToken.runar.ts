import { StatefulSmartContract, assert, checkSig, len } from 'runar-lang';
import type { PubKey, Sig, Addr } from 'runar-lang';

/**
 * WalletToken -- the token ABI the SDKs' `TokenWallet` helper is written for.
 *
 * `TokenWallet` (TS, Go, Rust, Python, Ruby SDKs) assumes a stateful contract
 * with state `supply` and `holder`, a `transfer(sig, to: Addr)` method and a
 * `merge(sig, otherSupply, otherHolder)` method. This is that contract, so the
 * wallet has something real to drive. The SDK end-to-end tests compile THIS
 * file (e.g. `packages/runar-sdk/src/__tests__/n042-token-wallet-example-e2e.test.ts`).
 *
 * NOT A SOUND TOKEN -- hence `naive-INSECURE`. Two limits follow from the ABI
 * itself and cannot be fixed without changing it:
 *
 * - `transfer` cannot hand the token to `to`: `holder` is a PubKey (needed by
 *   `checkSig`), `to` is an Addr (a hash160), and the method receives no
 *   public key to store. It authorises the spend and checks `to` is 20 bytes;
 *   the continuation keeps the same holder.
 * - `merge` cannot authenticate its companion input. Nothing in
 *   `(sig, otherSupply, otherHolder)` binds another input's outpoint or
 *   script, so the holder can call `merge` on ONE input with a made-up
 *   `otherSupply` and inflate the supply. TokenWallet spends both inputs, each
 *   carrying the other's values, and `hashOutputs` forces them to agree --
 *   but the contract does not REQUIRE a second input.
 *
 * For a token whose transfer re-keys the owner and whose merge proves its
 * companion (parent-tx walk over `allPrevouts`), see `examples/ts/token-ft/`.
 */
class WalletToken extends StatefulSmartContract {
  supply: bigint;
  holder: PubKey;

  constructor(supply: bigint, holder: PubKey) {
    super(supply, holder);
    this.supply = supply;
    this.holder = holder;
  }

  public transfer(sig: Sig, to: Addr) {
    assert(checkSig(sig, this.holder));
    assert(len(to) === 20n);
  }

  public merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey) {
    assert(checkSig(sig, this.holder));
    assert(otherHolder === this.holder);
    assert(otherSupply >= 0n);
    this.supply = this.supply + otherSupply;
  }
}
