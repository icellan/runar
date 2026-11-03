/**
 * The one way the off-chain acceptance oracles build an `@bsv/sdk` `Spend`
 * (F-055 / CL-BUG-073).
 *
 * `Spend.isRelaxed()` is `isRelaxed || transactionVersion > 1` — the Chronicle
 * rule under which a version > 1 transaction opts out of the unlocking-script
 * malleability restrictions: push-only unlocking, clean stack, minimal push,
 * minimal script-number decoding, low-S and NULLDUMMY. Every transaction this
 * repo's SDK builds is VERSION 1 (`new Transaction()`), so that is what a real
 * broadcast of an SDK-built spend faces: the strict set.
 *
 * `real-crypto-execution.ts`'s stateless-signed leg and `script-execution.ts`
 * used to build their `Spend` at version 2 and judged every spend relaxed,
 * reporting witnesses no node would relay as accepted. Routing every oracle
 * `Spend` through here makes that impossible to reintroduce silently: a
 * version other than 1, or an explicit `isRelaxed`, throws instead of quietly
 * weakening the verdict.
 *
 * `ScriptVM` (`vm/script-vm.ts`) is deliberately NOT routed here: it is a
 * fragment runner/debugger, not an acceptance oracle, and exposes the relaxed
 * mode as its documented default (`flags.strictEncoding` opts back in).
 */
import { Spend } from '@bsv/sdk';

type SpendParams = ConstructorParameters<typeof Spend>[0];

/** The transaction version every oracle `Spend` is built (and signed) at. */
export const CONSENSUS_TX_VERSION = 1;

/**
 * The synthetic single-input, zero-output spend context the stateless oracles
 * sign and validate against. Same values as `ScriptVM`'s
 * `SYNTHETIC_SPEND_CONTEXT`, so a signature built for one verifies on the other.
 */
export const CONSENSUS_SPEND_CONTEXT = {
  sourceTXID: '00'.repeat(32),
  sourceOutputIndex: 0,
  sourceSatoshis: 100_000,
  transactionVersion: CONSENSUS_TX_VERSION,
  inputIndex: 0,
  inputSequence: 0xffffffff,
  lockTime: 0,
} as const;

/**
 * `new Spend(params)` under the strict (version-1) consensus rule set. Throws
 * if `params` would put `Spend` in relaxed mode.
 */
export function newConsensusSpend(params: Omit<SpendParams, 'isRelaxed'>): Spend {
  if ((params as SpendParams).isRelaxed === true) {
    throw new Error(
      'newConsensusSpend: isRelaxed is refused — an acceptance oracle must apply the ' +
        'consensus malleability rules (push-only, clean stack, minimal push/number, low-S, NULLDUMMY)',
    );
  }
  if (params.transactionVersion !== CONSENSUS_TX_VERSION) {
    throw new Error(
      `newConsensusSpend: transaction version ${params.transactionVersion} is refused — ` +
        '@bsv/sdk treats version > 1 as relaxed and skips the consensus malleability rules; ' +
        `every SDK-built transaction is version ${CONSENSUS_TX_VERSION}`,
    );
  }
  return new Spend({ ...params, isRelaxed: false });
}
