/**
 * N-064 — execution proof: constant folding (ON by default) no longer folds
 * with a constant a name no longer holds.
 *
 * Every tier's folder recorded a name's constant when a binding produced one
 * and never dropped it. A name can be bound more than once, and the probes
 * that showed it bound a user local to the name of an earlier compiler temp:
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
 * N-065 made the naming collision itself a refusal: every tier now rejects
 * those four sources (a local may not be spelled like an ANF temp), so the
 * source path to this fold defect is closed. The fold must still be right for
 * the ANF shape, so the test replays the EXACT ANF each probe lowered to
 * (`conformance/negatives/n064-collision-anf.json`, generated with
 * parse -> lowerToANF and no validator) through `foldConstants`. With the
 * pre-N-064 folder that replay reproduces every `staleFoldOn` script below
 * byte for byte; with the current folder it gives the fold-OFF script.
 *
 * Oracle: `@bsv/sdk` Spend under consensus rules (`newConsensusSpend`). The
 * attack inputs are the crafted ones the stale scripts accepted; the stale
 * scripts are checked too, so the oracle is shown to see the defect.
 *
 * What this proves: (1) all seven tiers refuse the four probe sources with the
 * N-065 diagnostic; (2) the reference folder, on the collision ANF, gives the
 * fold-OFF script, which Spend rejects for Rebind p = 1, IfStale p = 5 c = true,
 * LoopStale p = 5 and RebindEq p = 1 and accepts for the honest RebindEq p = 5,
 * while every stale script decides the opposite way. The six native folders are
 * pinned to the same fold-OFF bytes on the same ANF by each tier's own n064 test.
 * What it does NOT prove: that no other fold rule is unsound, or that no other
 * source shape rebinds a name that held a constant (the plain `let x = 0n;
 * x = p` reassignment lowers through an `@ref` alias and did not reproduce).
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { compile, compileFromANF, foldConstants, loadANFFromJSON } from 'runar-compiler';
import { LockingScript, UnlockingScript } from '@bsv/sdk';
import { CONSENSUS_SPEND_CONTEXT, newConsensusSpend } from '../consensus-spend.js';

const REPO = join(__dirname, '..', '..', '..', '..');
const TMP = mkdtempSync(join(tmpdir(), 'runar-n064-'));

interface Probe {
  name: string;
  source: string;
  ir: unknown;
  foldOff: string;
  staleFoldOn: string;
}
const PROBES = (
  JSON.parse(
    readFileSync(join(REPO, 'conformance', 'negatives', 'n064-collision-anf.json'), 'utf8'),
  ) as { probes: Probe[] }
).probes;
const probe = (name: string): Probe => PROBES.find((p) => p.name === name)!;

/** The local each probe spells like a temp — the name N-065 refuses. */
const COLLIDING_LOCAL: Record<string, string> = {
  Rebind: 't1',
  RebindEq: 't1',
  IfStale: 't2',
  LoopStale: 't2',
};
const n065Message = (name: string): string =>
  `'${name}' is reserved for compiler-generated names and cannot be used as an identifier`;

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

/** A native CLI's verdict on a source file: exit status and all its output. */
function nativeCompile(tier: string, file: string, src: string): { status: number | null; out: string } {
  const { cmd, pre, cwd } = NATIVE[tier]!();
  const r = spawnSync(cmd, [...pre, '--source', writeTmp(file, src), '--hex'], {
    cwd,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${cmd} failed to start: ${r.error.message}`);
  return { status: r.status, out: `${r.stdout ?? ''}\n${r.stderr ?? ''}` };
}

/** Spend `lockingHex` with the push-only `unlockingHex` under consensus rules. */
function spends(lockingHex: string, unlockingHex: string): boolean {
  try {
    return newConsensusSpend({
      ...CONSENSUS_SPEND_CONTEXT,
      lockingScript: LockingScript.fromHex(lockingHex),
      unlockingScript: UnlockingScript.fromHex(unlockingHex),
      otherInputs: [],
      outputs: [],
    }).validate();
  } catch {
    return false;
  }
}

/** The fold-ON script of a probe's collision ANF, from the reference folder. */
function foldOnHex(p: Probe): string {
  return compileFromANF(foldConstants(loadANFFromJSON(JSON.stringify(p.ir)))).scriptHex;
}

describe('N-064 / N-065 — the collision probes are refused from source in every tier', () => {
  for (const p of PROBES) {
    const file = `${p.name}.runar.ts`;
    const want = n065Message(COLLIDING_LOCAL[p.name]!);

    it(`ts refuses ${file}`, () => {
      const r = compile(p.source, { fileName: file });
      expect(r.success).toBe(false);
      expect(r.diagnostics.map((d) => d.message)).toContain(want);
    });

    for (const tier of Object.keys(NATIVE)) {
      it(`${tier} refuses ${file}`, () => {
        const { status, out } = nativeCompile(tier, file, p.source);
        expect(status, `${tier} accepted ${file}: ${out}`).not.toBe(0);
        expect(out).toContain(want);
      });
    }
  }
});

describe('N-064 — the reference folder on the collision ANF', () => {
  for (const p of PROBES) {
    it(`${p.name}: fold-ON equals the fold-OFF script, not the stale one`, () => {
      expect(compileFromANF(loadANFFromJSON(JSON.stringify(p.ir))).scriptHex).toBe(p.foldOff);
      expect(p.foldOff).not.toBe(p.staleFoldOn);
      expect(foldOnHex(p)).toBe(p.foldOff);
    });
  }
});

describe('N-064 — fold-ON scripts on the Spend engine', () => {
  // Unlocking scripts are the minimal pushes of the arguments, in order.
  const attacks: Array<{ name: string; args: string; why: string }> = [
    { name: 'Rebind', args: '51', why: 'unlock(1): 1 + 1 != 1' },
    { name: 'IfStale', args: '5551', why: 'unlock(5, true): t2 = 5 after the if' },
    { name: 'LoopStale', args: '55', why: 'unlock(5): t2 = 5 from iteration 1 on' },
    { name: 'RebindEq', args: '51', why: 'unlock(1): 1 != 5' },
  ];

  for (const a of attacks) {
    it(`ATTACK ${a.name} ${a.why} — the stale script accepts it, the fold-ON script rejects it`, () => {
      const p = probe(a.name);
      expect(spends(p.staleFoldOn, a.args), 'the oracle must see the pre-fix defect').toBe(a.name !== 'RebindEq');
      expect(spends(foldOnHex(p), a.args)).toBe(false);
    });
  }

  it('honest RebindEq unlock(5) is ACCEPTED (the guard reads p, not the stale 0)', () => {
    const p = probe('RebindEq');
    expect(spends(p.staleFoldOn, '55'), 'the stale guard folded to FALSE').toBe(false);
    expect(spends(foldOnHex(p), '55')).toBe(true);
  });
});
