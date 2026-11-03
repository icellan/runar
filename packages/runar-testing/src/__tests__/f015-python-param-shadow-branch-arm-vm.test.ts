/**
 * F-015 — Python tier: a method parameter that shadows a MUTABLE property was
 * read from the stale on-chain STATE inside an `if` arm, not from the caller's
 * witness argument. A guard in the arm therefore checked the wrong value:
 *
 *     count: bigint;                                  // on-chain state = 5
 *     public set(count: bigint, flag: boolean) {
 *       if (flag) { assert(count == 5n); }            // the ARGUMENT must be 5
 *       this.count = count;
 *     }
 *
 * The source says `set(7n, true)` must fail (`7 == 5` is false). Python's
 * then-arm emitted `OP_IF OP_DUP OP_5 OP_NUMEQUALVERIFY` — `OP_DUP` copies the
 * deserialized state value (5) sitting on top — so the attacker's spend was
 * ACCEPTED and the contract's state moved to 7 past a guard that forbids it.
 *
 * Root cause (`compilers/python/runar_compiler/codegen/stack.py` `_lower_if`):
 * arms lower in a fresh `_LoweringContext` whose `renamed_params` (issue #130)
 * started empty, so `load_param('count')` in the arm resolved the bare name to
 * the deserialized property slot instead of the reserved `__param_count` slot.
 *
 * The acceptance oracle is the real `@bsv/sdk` `Spend` engine: the Python
 * CLI's artifact is deployed and called through the TS SDK, and the call's
 * contract input is replayed with `validateContractInput`. Expected verdicts
 * are derived BY HAND from the source, never from compiler output.
 *
 * What this proves: the Python-compiled script enforces an in-arm guard on the
 * caller's argument, rejects the crafted shadow-read attack, and still accepts
 * the honest spends with the correct continuation state.
 * What it does NOT prove: anything about the other tiers. At the time of the
 * fix the TS, Go, Rust, Zig and Ruby tiers emitted the SAME fail-open bytes as
 * pre-fix Python (their arm contexts drop `renamedParams` too); only Java
 * copied the map. That is a separate cross-tier item, not covered here.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const FILE = 'Probe.runar.ts';

const SRC = `import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(count == 5n);
    }
    this.count = count;
  }
}
`;

function compileWithPython(source: string): RunarArtifact {
  const dir = mkdtempSync(join(tmpdir(), 'runar-f015-'));
  const path = join(dir, FILE);
  writeFileSync(path, source);
  const r = spawnSync('python3', ['-m', 'runar_compiler', '--source', path], {
    cwd: join(REPO, 'compilers', 'python'),
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (r.error) throw new Error(`python3 failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`python compile failed (${r.status}): ${r.stderr}`);
  return JSON.parse(r.stdout) as RunarArtifact;
}

interface Verdict {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
  state?: Record<string, unknown>;
}

/** Deploy the Python artifact with on-chain `count = state`, call `set`, and
 *  replay the contract input on the real Spend engine. */
async function spend(artifact: RunarArtifact, state: bigint, count: bigint, flag: boolean): Promise<Verdict> {
  const key = testKey('alice');
  const signer = new LocalSigner(key.privKey);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: key.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(key.pubKey),
  });
  const contract = new RunarContract(artifact, [state]);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  try {
    // dryRun: the SDK replays the contract input on the real Spend engine
    // before broadcast and throws a message unique to a script rejection.
    await contract.call('set', [count, flag], provider, signer, { dryRun: true });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error,
    };
  }
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  return {
    accepted: validateContractInput(callTx, 0, deployTx, 0),
    reachedEngine: true,
    state: contract.state as Record<string, unknown>,
  };
}

describe('F-015 — Python: a shadowing param read inside an if-arm is the witness argument', () => {
  const artifact = compileWithPython(SRC);
  const STATE = 5n;

  it('ATTACK set(7, true) with on-chain count = 5 is REJECTED (the arm must check 7, not the state)', async () => {
    const v = await spend(artifact, STATE, 7n, true);
    expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
    expect(v.accepted, 'the arm read the stale state value instead of the argument').toBe(false);
  });

  it('honest set(5, true) is ACCEPTED and commits count = 5', async () => {
    const v = await spend(artifact, STATE, 5n, true);
    expect(v.accepted, v.error).toBe(true);
    expect(v.state).toEqual({ count: 5n });
  });

  it('CONTROL set(7, false) skips the arm, is ACCEPTED and commits count = 7', async () => {
    const v = await spend(artifact, STATE, 7n, false);
    expect(v.accepted, v.error).toBe(true);
    expect(v.state).toEqual({ count: 7n });
  });

  it('CONTROL on-chain count = 7: honest set(5, true) is ACCEPTED (guard reads the argument, not the state)', async () => {
    const v = await spend(artifact, 7n, 5n, true);
    expect(v.accepted, v.error).toBe(true);
    expect(v.state).toEqual({ count: 5n });
  });
});
