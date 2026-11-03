import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivateKey } from '@bsv/sdk';
import {
  executeOnChainAuthoritative,
  AssertionFailureError,
} from '../../packages/runar-sdk/src/index.js';
import { ScriptExecutionContract } from '../../packages/runar-testing/src/script-execution.js';
import type { ANFProgram } from '../../packages/runar-ir-schema/src/index.js';
import { enforceDriverGate } from './driver-gate.js';

// ---------------------------------------------------------------------------
// N-197 — every SDK ANF interpreter, in on-chain mode, answered `false` from
// `checkSig` on a malformed signature or public-key encoding. The compiled
// script does not: `checkSig` is a bare OP_CHECKSIG, and @bsv/sdk `Spend`
// runs `checkSignatureEncoding` + `checkPublicKeyEncoding` first and ABORTS
// the script when either fails. Under `assert(checkSig(...))` that is
// invisible (both reject); under `checkSig(a, A) || checkSig(b, B)` the
// interpreter took the B-arm and reported a VALID spend the chain aborts on.
// F-227 fixed the same defect in runar-testing's interpreter; this is the
// seven SDK interpreters' counterpart.
//
// One shared vector file (`checksig-encoding/vectors.json`) is replayed
// through three engines:
//
//   - the ORACLE: the probe compiled and run on @bsv/sdk `Spend.validate()`
//     (`ScriptExecutionContract.executeSigned`, version-1 consensus rules),
//     with sigB re-signed over the real sighash so the B-arm is satisfiable.
//     The abort verdict of every vector is taken from it on every run, not
//     from the file.
//   - the TS SDK reference `executeOnChainAuthoritative`, in-process;
//   - the six per-SDK drivers (`--mode=on-chain`), over the same vectors.
//
// Each tier surfaces the abort through the channel its OP_SPLIT aborts already
// use: a plain error (exit != 0, stderr carrying "OP_CHECKSIG aborts" and the
// gate that fired) in TS / Go / Python / Ruby / Java, `error.ScriptNumberError`
// in Zig (no message channel), and an AssertionFailureError at the CALL
// binding (`t2`, the `checkSig(sigA, pubA)` binding — not the final assert)
// in Rust.
//
// N-198 adds NULLFAIL (BIP146) to the same vectors, per user decision R73.2:
// a NON-EMPTY, well-formed signature that does not verify aborts the script on
// a BSV node (ARC answers 461), so every SDK interpreter now aborts there too,
// with the reason "the signature is non-empty and does not verify
// (NULLFAIL)". The arm that must fail takes an EMPTY signature (`EMPTY_SIG`,
// issue #106), which still pushes false. `Spend` has NO NULLFAIL rule (it
// pushes false for a wrong-key signature), so for the `nullfail` vectors Spend
// is NOT the oracle: the oracle is the consensus rule as a node enforces it
// (witnessed on regtest by integration/ts/nullfail-multimethod.test.ts and its
// per-tier peers). The Spend describe still runs those vectors and pins that
// Spend falls through to the B-arm — it documents the divergence, it does not
// adjudicate it.
//
// What this proves: for the three F-227 malformed encodings (corrupted DER
// length, high S, unknown pubkey prefix) plus an off-curve uncompressed key,
// and (N-255, user decision R105) a signature that verifies but is bare DER
// with no trailing sighash-type byte, every SDK interpreter aborts where
// Spend aborts; for the two NULLFAIL
// vectors (a wrong-key signature against a compressed and an uncompressed
// key) every interpreter aborts where a node aborts; for the three controls
// (empty signature against a compressed and an uncompressed key, and a sigA
// that verifies) every one succeeds — the first two through the B-arm.
//
// What this does not prove: (a) anything about the VALUE of the sighash-type
// byte — Spend's encoding gate does not check it, and neither do the
// interpreters; (b) `checkMultiSig` — its encoding
// gates and NULLFAIL are pinned separately by ./checkmultisig-onchain.test.ts
// (N-259);
// (c) the NULLFAIL verdict against a node — no engine in this file enforces
// NULLFAIL independently of the interpreters; (d) anything about a node
// beyond `Spend` for the encoding vectors.
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const DRIVERS_DIR = join(__dirname, 'drivers');
const ANF_PATH = join(__dirname, 'programs', 'checksig-or-probe.anf.json');
const SOURCE_PATH = join(__dirname, 'programs', 'CheckSigOrProbe.runar.ts');
const VECTORS_PATH = join(__dirname, 'checksig-encoding', 'vectors.json');

/** The ANF binding of `checkSig(sigA, pubA)` — the Rust tier's abort binding. */
const SIG_A_BINDING = 't2';
const SHARED_DIAGNOSTIC = /OP_CHECKSIG aborts/;
const PRIV_B = '22'.repeat(32);

interface Vector {
  name: string;
  sigA: string;
  pubA: string;
  aborts: boolean;
  /** N-198: aborts on a node under NULLFAIL; Spend (no NULLFAIL) does not. */
  nullfail?: boolean;
  reason?: string;
}
interface Vectors {
  sighash: string;
  sigB: string;
  pubB: string;
  cases: Vector[];
}

const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as Vectors;
const anf = JSON.parse(readFileSync(ANF_PATH, 'utf8')) as ANFProgram;
const SUCCESS = { state: {}, dataOutputs: [], rawOutputs: [] };

function argsFor(v: Vector): Record<string, unknown> {
  return { sigA: v.sigA, pubA: v.pubA, sigB: vectors.sigB, pubB: vectors.pubB };
}

describe('N-197: the vectors and the probe are what they claim', () => {
  it('the probe ANF short-circuits checkSig(sigA, pubA) into checkSig(sigB, pubB)', () => {
    const unlock = anf.methods.find(m => m.name === 'unlock')!;
    const a = unlock.body.find(b => b.name === SIG_A_BINDING)!;
    expect(a.value).toMatchObject({ kind: 'call', func: 'checkSig', args: ['t0', 't1'] });
    const orIf = unlock.body.find(b => b.value.kind === 'if')!;
    expect(orIf.value).toMatchObject({ kind: 'if', cond: SIG_A_BINDING });
    const elseCalls = (orIf.value as { else: Array<{ value: { kind: string; func?: string } }> }).else
      .filter(b => b.value.kind === 'call' && b.value.func === 'checkSig');
    expect(elseCalls).toHaveLength(1);
  });

  it('carries both verdicts', () => {
    expect(vectors.cases.filter(c => c.aborts && !c.nullfail).length).toBeGreaterThanOrEqual(3);
    expect(vectors.cases.filter(c => c.nullfail).length).toBeGreaterThanOrEqual(2);
    expect(vectors.cases.filter(c => !c.aborts).length).toBeGreaterThanOrEqual(3);
  });

  it('every NULLFAIL vector is a well-formed, non-empty signature (not an encoding abort)', () => {
    for (const v of vectors.cases.filter(c => c.nullfail)) {
      expect(v.aborts).toBe(true);
      expect(v.sigA.length).toBeGreaterThan(0);
    }
    // At least one non-aborting control is the empty signature (EMPTY_SIG).
    expect(vectors.cases.some(c => !c.aborts && c.sigA === '')).toBe(true);
  });
});

describe('N-197 oracle: Spend.validate() on the compiled probe', () => {
  const script = ScriptExecutionContract.fromSource(
    readFileSync(SOURCE_PATH, 'utf8'), {}, 'CheckSigOrProbe.runar.ts',
  );
  for (const v of vectors.cases) {
    // A `nullfail` vector: Spend has no NULLFAIL and pushes false, so it falls
    // through to sigB. That is Spend's verdict, not a node's (see header).
    const spendAborts = v.aborts && !v.nullfail;
    it(`${v.name} → ${spendAborts ? 'abort' : 'falls through to sigB'}`, () => {
      const r = script.executeSigned('unlock', [v.sigA, v.pubA, '', vectors.pubB], 2, PrivateKey.fromHex(PRIV_B));
      if (spendAborts) {
        expect(r.success).toBe(false);
        expect(r.error).toMatch(/signature format is invalid|public key/i);
      } else {
        expect(r).toEqual({ success: true });
      }
    });
  }
});

describe('N-197: TS SDK executeOnChainAuthoritative', () => {
  for (const v of vectors.cases) {
    it(`${v.name} → ${v.aborts ? 'abort' : 'succeeds'}`, () => {
      const run = () => executeOnChainAuthoritative(
        anf, 'unlock', {}, argsFor(v), [], { sighash: vectors.sighash },
      );
      if (v.aborts) {
        let err: unknown;
        try { run(); } catch (e) { err = e; }
        expect(err).toBeInstanceOf(Error);
        expect(err).not.toBeInstanceOf(AssertionFailureError);
        expect((err as Error).message).toMatch(SHARED_DIAGNOSTIC);
        expect((err as Error).message).toContain(v.reason!);
      } else {
        const r = run();
        expect(r.state).toEqual({});
      }
    });
  }
});

// ---------------------------------------------------------------------------
// Per-SDK drivers.
// ---------------------------------------------------------------------------

type AbortChannel = 'message' | 'zig-error' | 'assert-at-call';

interface DriverConfig {
  name: string;
  binary: string;
  prefix?: string[];
  setupHint: string;
  abort: AbortChannel;
}

const javaJar = [
  join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar'),
  join(DRIVERS_DIR, 'java', 'build', 'libs', 'java-anf-driver.jar'),
].find(existsSync) ?? join(DRIVERS_DIR, 'java', 'build', 'libs', 'runar-anf-driver.jar');

const driverConfigs: DriverConfig[] = [
  { name: 'python', prefix: ['python3'], binary: join(DRIVERS_DIR, 'python', 'driver.py'), abort: 'message',
    setupHint: 'python3 must be on PATH; driver script lives at drivers/python/driver.py.' },
  { name: 'ruby', prefix: ['ruby'], binary: join(DRIVERS_DIR, 'ruby', 'driver.rb'), abort: 'message',
    setupHint: 'ruby must be on PATH; driver script lives at drivers/ruby/driver.rb.' },
  { name: 'go', prefix: ['go', 'run'], binary: join(DRIVERS_DIR, 'go', 'driver.go'), abort: 'message',
    setupHint: 'go must be on PATH; driver lives at drivers/go/driver.go.' },
  { name: 'rust', binary: join(DRIVERS_DIR, 'rust', 'target', 'release', 'runar-anf-driver-rust'), abort: 'assert-at-call',
    setupHint: 'cargo build --release inside drivers/rust/.' },
  { name: 'java', prefix: ['java', '-jar'], binary: javaJar, abort: 'message',
    setupHint: 'gradle fatJar --no-daemon inside drivers/java/.' },
  { name: 'zig', binary: join(DRIVERS_DIR, 'zig', 'zig-out', 'bin', 'runar-anf-driver-zig'), abort: 'zig-error',
    setupHint: 'zig build -Doptimize=ReleaseSafe inside drivers/zig/.' },
];

const isDriverAvailable = (cfg: DriverConfig) => existsSync(cfg.binary);
enforceDriverGate('N-197 checkSig encoding-abort', driverConfigs.filter(c => !isDriverAvailable(c)), process.env);

const inputDir = mkdtempSync(join(tmpdir(), 'runar-n197-'));

function writeInput(v: Vector, i: number): string {
  const path = join(inputDir, `case-${i}.json`);
  writeFileSync(path, JSON.stringify({
    anfPath: ANF_PATH,
    methodName: 'unlock',
    currentState: {},
    args: argsFor(v),
    constructorArgs: [],
    sighash: vectors.sighash,
  }));
  return path;
}

for (const cfg of driverConfigs) {
  describe.skipIf(!isDriverAvailable(cfg))(`N-197: ${cfg.name} SDK on-chain driver`, () => {
    vectors.cases.forEach((v, i) => {
      it(`${v.name} → ${v.aborts ? 'abort' : 'succeeds'}`, () => {
        const argv = [...(cfg.prefix ?? []), cfg.binary, '--mode=on-chain', writeInput(v, i)];
        const r = spawnSync(argv[0]!, argv.slice(1), {
          cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'],
        });
        const stdout = (r.stdout ?? '').trim();
        const stderr = r.stderr ?? '';
        if (!v.aborts) {
          expect(r.status, `${cfg.name} exited ${r.status}: ${stderr}`).toBe(0);
          expect(JSON.parse(stdout)).toEqual(SUCCESS);
          return;
        }
        if (cfg.abort === 'assert-at-call') {
          expect(r.status, stderr).toBe(0);
          // At the checkSig call binding, NOT the final assert (t8): an
          // assert-binding failure would mean the A-arm answered false.
          expect(JSON.parse(stdout)).toEqual({
            error: 'AssertionFailureError', methodName: 'unlock', bindingName: SIG_A_BINDING,
          });
          return;
        }
        expect(r.status, `${cfg.name} did not abort; stdout: ${stdout}`).not.toBe(0);
        expect(stdout).toBe('');
        if (cfg.abort === 'zig-error') {
          expect(stderr).toMatch(/ScriptNumberError/);
        } else {
          expect(stderr).toMatch(SHARED_DIAGNOSTIC);
          expect(stderr).toContain(v.reason!);
        }
      });
    });
  });
}
