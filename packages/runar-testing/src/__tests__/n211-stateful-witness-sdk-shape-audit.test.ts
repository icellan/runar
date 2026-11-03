/**
 * N-211: the stateful real-crypto witness builds its spend through the SDK
 * (`RunarContract.deploy` / `.call`), so before this item it validated
 * WHATEVER transaction the SDK happened to build. A deliberate SDK
 * tx-modelling mutation that still yields a consensus-valid transaction —
 * `call()` silently ignoring the requested continuation amount or nLockTime,
 * `deploy()` ignoring the requested contract-output amount — slipped straight
 * through: the Spend engine accepted, the state pin matched, the witness
 * passed while exercising a different transaction from the one its spec
 * describes.
 *
 * Each case below injects one such mutation by wrapping the real SDK method
 * and dropping one option, then asserts `runStatefulSpend` refuses with the
 * N-211 audit error instead of reporting a verdict. A control case proves the
 * honest SDK passes the same audit.
 *
 * What this proves: the parts of the transaction a witness spec controls
 * (spent outpoint, nLockTime, input nSequence, deploy and continuation
 * amounts) are checked from the raw `@bsv/sdk` transaction against the spec
 * itself, not against the SDK's own model of it.
 *
 * What this does NOT prove: anything about the parts the SDK still models
 * alone — the unlocking-script layout and its implicit parameters, the change
 * output, fee, constructor-argument splicing and initial-state serialisation
 * of the deploy. Those are covered (only) by the Spend verdict: a wrong value
 * there makes the compiled script reject, but a wrong-but-valid one is not
 * seen. See the module docstring of `oracle/real-crypto-execution.ts`.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { RunarContract } from 'runar-sdk';
import { runStatefulSpend } from '../oracle/index.js';

const CONFORMANCE = resolve(__dirname, '../../../../conformance/tests');

function readContract(name: string): { source: string; fileName: string } {
  const manifest = JSON.parse(
    readFileSync(resolve(CONFORMANCE, name, 'source.json'), 'utf8'),
  ) as { sources: Record<string, string> };
  const rel = manifest.sources['.runar.ts'];
  if (!rel) throw new Error(`${name}: source.json has no '.runar.ts' entry`);
  return { source: readFileSync(resolve(CONFORMANCE, name, rel), 'utf8'), fileName: rel.split('/').pop()! };
}

type AnyFn = (...a: unknown[]) => Promise<unknown>;

/** Wrap `RunarContract.prototype[method]` so the options object (its last
 *  argument) loses `key` — a mutated SDK that ignores one requested field. */
function dropOption(method: 'call' | 'deploy', key: string): void {
  const orig = RunarContract.prototype[method] as unknown as AnyFn;
  vi.spyOn(RunarContract.prototype, method).mockImplementation(function (
    this: RunarContract,
    ...args: unknown[]
  ) {
    const last = args[args.length - 1];
    if (last && typeof last === 'object') {
      const copy = { ...(last as Record<string, unknown>) };
      delete copy[key];
      args[args.length - 1] = copy;
    }
    return orig.apply(this, args);
  } as never);
}

describe('N-211: stateful witness audits the SDK-built tx against its spec', () => {
  const { source, fileName } = readContract('stateful-counter');
  // stateful-counter.json's F-024 deposit witness: 10000 -> 12000, count 5 -> 6.
  const deposit = {
    source,
    fileName,
    method: 'increment',
    args: [],
    constructorArgs: [5n],
    signerKey: 'alice',
    deploySatoshis: 10000,
    satoshis: 12000,
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('control: the honest SDK passes the audit and the spend verifies', async () => {
    const r = await runStatefulSpend({ ...deposit, lockTime: 500000 });
    expect(r.vmAccepted, r.vmError).toBe(true);
    expect(r.continuationState).toEqual({ count: 6n });
  });

  it('catches call() ignoring the requested continuation amount', async () => {
    dropOption('call', 'satoshis');
    await expect(runStatefulSpend(deposit)).rejects.toThrow(/N-211 SDK tx-shape audit: .*continuation output/);
  });

  it('catches call() ignoring the requested nLockTime', async () => {
    dropOption('call', 'locktime');
    await expect(runStatefulSpend({ ...deposit, lockTime: 500000 })).rejects.toThrow(
      /N-211 SDK tx-shape audit: .*nLockTime/,
    );
  });

  it('catches deploy() ignoring the requested contract-output amount', async () => {
    dropOption('deploy', 'satoshis');
    await expect(runStatefulSpend({ ...deposit, satoshis: undefined })).rejects.toThrow(
      /N-211 SDK tx-shape audit: .*deploy output/,
    );
  });
});
