import { StatefulSmartContract } from 'runar-lang';

/**
 * #197 — only `update_prop` changes a property. `addOutput(sats, ...values)`
 * serialises its values into ITS OWN output script and does not write the
 * property that later `this.count` reads load, on-chain. An interpreter that
 * writes the property on `addOutput` evaluates a second output from the first
 * output's value and builds a continuation the covenant rejects.
 *
 * fanOut:      no update_prop between the two addOutputs.
 *              outputs carry count+1 and count+100; last write = count+100.
 * bumpBetween: addOutput; update_prop; addOutput.
 *              outputs carry count+1 and (count+5)+100; last write = count+105.
 */
class AddOutputEnv extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public fanOut() {
    this.addOutput(1000n, this.count + 1n);
    this.addOutput(1000n, this.count + 100n);
  }

  public bumpBetween() {
    this.addOutput(1000n, this.count + 1n);
    this.count = this.count + 5n;
    this.addOutput(1000n, this.count + 100n);
  }
}
