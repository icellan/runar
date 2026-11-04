import { StatefulSmartContract, extractAmount } from 'runar-lang';

/**
 * Ports #172 — a value-returning private helper that reads `this.txPreimage`.
 * The helper stays a `method_call` in the ANF and its body starts with
 * `load_prop txPreimage`, so the helper's env must carry the caller's
 * `txPreimage` binding for `extractAmount` to answer the spent UTXO's value.
 * The committed state is `total + <input satoshis>`; an interpreter that drops
 * the binding answers the 32-zero-byte placeholder inside the helper instead.
 */
class HelperExtractAmount extends StatefulSmartContract {
  total: bigint;

  constructor(total: bigint) {
    super(total);
    this.total = total;
  }

  private spent(): bigint {
    return extractAmount(this.txPreimage);
  }

  public tick() {
    this.total = this.total + this.spent();
  }
}
