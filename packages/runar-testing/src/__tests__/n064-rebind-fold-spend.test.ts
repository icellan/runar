/**
 * N-064 — execution proof, all seven tiers: constant folding (ON by default)
 * no longer folds with a constant a name no longer holds.
 *
 * Every tier's folder recorded a name's constant when a binding produced one
 * and never dropped it. A name can be bound more than once — a reassignment,
 * or a user local that shares an earlier compiler temp's name (the naming
 * collision itself is N-065 and is NOT changed here) — so later uses folded
 * with a stale value:
 *
 *     Rebind:    assert(p > 0n); let t1: bigint = p; assert(t1 + 1n === 1n);
 *                (`0n` lowers to temp t1; the local rebinds t1 to p)
 *     RebindEq:  assert(p > 0n); let t1: bigint = p; assert(t1 === 5n);
 *                (same collision; the stale t1 = 0 folded the guard to FALSE,
 *                so the honest p = 5 could never spend)
 *     IfStale:   let t2 = p; assert(p > 0n); if (c) { t2 = p; } assert(t2 + 1n === 1n);
 *                (`0n` lowers to temp t2; the arm rebinds t2, the pre-if
 *                constant survived the if)
 *     LoopStale: let t2 = p; assert(p > 0n); for (2x) { assert(t2 + 1n === 1n); t2 = p; }
 *                assert(t2 + 1n === 1n);
 *                (the body rebinds t2; the entry constant was used in every
 *                iteration and after the loop)
 *
 * With folding ON every tier folded the Rebind / IfStale / LoopStale final
 * guard to OP_TRUE (Rebind: `7600a0695151515177777777`), so the deployed
 * script accepted any p > 0, and folded the RebindEq guard to OP_FALSE.
 * The expected verdicts below are derived BY HAND from the source, and only
 * for inputs where the source and the compiler's fold-OFF reading of a
 * colliding `tN` agree (IfStale with c = false does not, which is N-065, so
 * it is deliberately not asserted): Rebind and LoopStale reject every p
 * (p > 0 and p + 1 == 1 cannot both hold); IfStale with c = true rejects
 * p = 5; RebindEq accepts p = 5 and rejects p = 1.
 *
 * Oracle: the real `@bsv/sdk` Spend engine (the SDK's pre-broadcast dry-run,
 * and `validateContractInput` for an accepted call). Each tier's CLI artifact,
 * compiled with folding ON (the default), is deployed and called through the
 * TS SDK. The attack inputs are the crafted ones the pre-fix scripts accepted.
 *
 * What this proves: for each of the seven tiers, the fold-ON script of each
 * probe is byte-identical to that tier's fold-OFF script and to every other
 * tier's, and Spend rejects the crafted attacks (Rebind p = 1, IfStale p = 5
 * c = true, LoopStale p = 5, RebindEq p = 1) while accepting the honest
 * RebindEq p = 5.
 * What it does NOT prove: that no other fold rule is unsound, or anything
 * about hostile `--ir` JSON (the fold is the same code path, but no `--ir`
 * probe is run here).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile } from 'runar-compiler';
import { RunarContract, MockProvider, LocalSigner, buildP2PKHScript } from 'runar-sdk';
import { Transaction } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { testKey, validateContractInput } from '../oracle/real-crypto-execution.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n064-'));

const REBIND = `import { SmartContract, assert } from 'runar-lang';

class Rebind extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint) {
    assert(p > 0n);
    let t1: bigint = p;
    assert(t1 + 1n === 1n);
  }
}
`;

const REBIND_EQ = `import { SmartContract, assert } from 'runar-lang';

class RebindEq extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint) {
    assert(p > 0n);
    let t1: bigint = p;
    assert(t1 === 5n);
  }
}
`;

const IF_STALE = `import { SmartContract, assert } from 'runar-lang';

class IfStale extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint, c: boolean) {
    let t2: bigint = p;
    assert(p > 0n);
    if (c) {
      t2 = p;
    }
    assert(t2 + 1n === 1n);
  }
}
`;

const LOOP_STALE = `import { SmartContract, assert } from 'runar-lang';

class LoopStale extends SmartContract {
  constructor() {
    super();
  }

  public unlock(p: bigint) {
    let t2: bigint = p;
    assert(p > 0n);
    for (let i: bigint = 0n; i < 2n; i++) {
      assert(t2 + 1n === 1n);
      t2 = p;
    }
    assert(t2 + 1n === 1n);
  }
}
`;

const PROBES: { file: string; src: string; staleFoldOn: string }[] = [
  { file: 'Rebind.runar.ts', src: REBIND, staleFoldOn: '7600a0695151515177777777' },
  { file: 'RebindEq.runar.ts', src: REBIND_EQ, staleFoldOn: '7600a06955007777' },
  { file: 'IfStale.runar.ts', src: IF_STALE, staleFoldOn: '767600877c51879b6978527900a0697c637c67777668775151515177777777' },
  {
    file: 'LoopStale.runar.ts',
    src: LOOP_STALE,
    staleFoldOn: '767800a0690051515151695579547a75515151515169597a547a7551515151777777777777777777777777',
  },
];

function requireBin(p: string, how: string): string {
  if (!existsSync(p)) throw new Error(`missing compiler binary ${p} — build it with: ${how}`);
  return p;
}

function javaJar(): string {
  const libs = join(REPO, 'compilers', 'java', 'build', 'libs');
  const jar = existsSync(libs) ? readdirSync(libs).find((f) => f.endsWith('.jar')) : undefined;
  if (!jar) throw new Error('Java jar missing — run `gradle jar` in compilers/java');
  return join(libs, jar);
}

function run(cmd: string, args: string[], cwd?: string): string {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120_000, maxBuffer: 32 * 1024 * 1024 });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

let seq = 0;
function writeTmp(fileName: string, src: string): string {
  const dir = join(TMP, String(seq++));
  mkdirSync(dir);
  const p = join(dir, fileName);
  writeFileSync(p, src);
  return p;
}

/** Native-tier CLI invocation (everything but the path and the mode flags). */
const NATIVE: Record<string, () => { cmd: string; pre: string[]; cwd?: string }> = {
  go: () => ({ cmd: requireBin(join(REPO, 'compilers', 'go', 'runar-go'), 'cd compilers/go && go build -o runar-go .'), pre: [] }),
  rust: () => ({ cmd: requireBin(join(REPO, 'compilers', 'rust', 'target', 'release', 'runar-compiler-rust'), 'cd compilers/rust && cargo build --release'), pre: [] }),
  python: () => ({ cmd: 'python3', pre: ['-m', 'runar_compiler'], cwd: join(REPO, 'compilers', 'python') }),
  zig: () => ({ cmd: requireBin(join(REPO, 'compilers', 'zig', 'zig-out', 'bin', 'runar-zig'), 'cd compilers/zig && zig build'), pre: [] }),
  ruby: () => ({ cmd: 'ruby', pre: ['-I', join(REPO, 'compilers', 'ruby', 'lib'), join(REPO, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')] }),
  java: () => ({ cmd: 'java', pre: ['-jar', javaJar()] }),
};

const TIER_NAMES = ['ts', ...Object.keys(NATIVE)];

function hex(tier: string, file: string, src: string, disableFold: boolean): string {
  if (tier === 'ts') {
    const r = compile(src, { fileName: file, disableConstantFolding: disableFold });
    if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    return r.artifact.script;
  }
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const fold = disableFold ? ['--disable-constant-folding'] : [];
  return run(cmd, [...pre, '--source', writeTmp(file, src), '--hex', ...fold], cwd).trim();
}

/** The artifact with folding ON — the default every user gets. */
function artifact(tier: string, file: string, src: string): RunarArtifact {
  if (tier === 'ts') {
    const r = compile(src, { fileName: file });
    if (!r.success || !r.artifact) throw new Error(JSON.stringify(r.diagnostics));
    return r.artifact as unknown as RunarArtifact;
  }
  if (tier === 'java') {
    const out = writeTmp('artifact.json', '');
    run('java', ['-jar', javaJar(), '--source', writeTmp(file, src), '--emit-artifact', out]);
    return JSON.parse(readFileSync(out, 'utf8'));
  }
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const art = JSON.parse(run(cmd, [...pre, '--source', writeTmp(file, src)], cwd));
  return art;
}

interface Verdict {
  accepted: boolean;
  reachedEngine: boolean;
  error?: string;
}

/** Deploy `art`, call `unlock(args)`, and replay the contract input on the
 *  real Spend engine. */
async function spend(art: RunarArtifact, args: (bigint | boolean)[]): Promise<Verdict> {
  const key = testKey('alice');
  const signer = new LocalSigner(key.privKey);
  const provider = new MockProvider();
  provider.addUtxo(await signer.getAddress(), {
    txid: key.privKey.slice(0, 64),
    outputIndex: 0,
    satoshis: 500_000,
    script: buildP2PKHScript(key.pubKey),
  });
  const contract = new RunarContract(art, []);
  await contract.deploy(provider, signer, {});
  const deployTx = Transaction.fromHex(provider.getBroadcastedTxs()[0]!);
  try {
    await contract.call('unlock', args, provider, signer, { dryRun: true });
  } catch (e) {
    const error = e instanceof Error ? e.message : String(e);
    return {
      accepted: false,
      reachedEngine: error.includes('local pre-broadcast dry-run rejected the primary contract input'),
      error,
    };
  }
  const callTx = Transaction.fromHex(provider.getBroadcastedTxs()[1]!);
  return { accepted: validateContractInput(callTx, 0, deployTx, 0), reachedEngine: true };
}

describe('N-064 — fold-ON bytes equal fold-OFF bytes, seven tiers', () => {
  for (const probe of PROBES) {
    it(`${probe.file}: every tier's fold-ON script equals the shared fold-OFF script`, () => {
      const off = hex('ts', probe.file, probe.src, true);
      expect(off).not.toBe(probe.staleFoldOn);
      for (const tier of TIER_NAMES) {
        expect(hex(tier, probe.file, probe.src, true), `${tier} fold-OFF diverges from ts`).toBe(off);
        const on = hex(tier, probe.file, probe.src, false);
        expect(on, `${tier} fold-ON still folds with a stale constant`).not.toBe(probe.staleFoldOn);
        expect(on, `${tier} fold-ON differs from fold-OFF`).toBe(off);
      }
    });
  }
});

for (const tier of TIER_NAMES) {
  describe(`N-064 [${tier}] — fold-ON scripts on the Spend engine`, () => {
    const rebind = artifact(tier, 'Rebind.runar.ts', REBIND);
    const rebindEq = artifact(tier, 'RebindEq.runar.ts', REBIND_EQ);
    const ifStale = artifact(tier, 'IfStale.runar.ts', IF_STALE);
    const loopStale = artifact(tier, 'LoopStale.runar.ts', LOOP_STALE);

    it('ATTACK Rebind unlock(1) is REJECTED (1 + 1 != 1)', async () => {
      const v = await spend(rebind, [1n]);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'the guard folded with the stale t1 = 0').toBe(false);
    });

    it('ATTACK IfStale unlock(5, true) is REJECTED (t2 = 5 after the if)', async () => {
      const v = await spend(ifStale, [5n, true]);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'the guard folded with the pre-if t2 = 0').toBe(false);
    });

    it('honest RebindEq unlock(5) is ACCEPTED (the guard reads p, not the stale 0)', async () => {
      const v = await spend(rebindEq, [5n]);
      expect(v.accepted, v.error).toBe(true);
    });

    it('ATTACK RebindEq unlock(1) is REJECTED (1 != 5)', async () => {
      const v = await spend(rebindEq, [1n]);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted).toBe(false);
    });

    it('ATTACK LoopStale unlock(5) is REJECTED (t2 = 5 from iteration 1 on)', async () => {
      const v = await spend(loopStale, [5n]);
      expect(v.reachedEngine, `never reached Spend: ${v.error ?? '(accepted)'}`).toBe(true);
      expect(v.accepted, 'the guard folded with the loop-entry t2 = 0').toBe(false);
    });
  });
}
