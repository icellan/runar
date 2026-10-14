import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ECDSA, Hash, LockingScript, PublicKey, Signature, BigNumber, TransactionSignature } from '@bsv/sdk';
import {
  executeOnChainAuthoritative,
  AssertionFailureError,
} from '../../packages/runar-sdk/src/index.js';
import { ScriptExecutionContract } from '../../packages/runar-testing/src/script-execution.js';
import { CONSENSUS_SPEND_CONTEXT } from '../../packages/runar-testing/src/consensus-spend.js';
import type { ANFProgram } from '../../packages/runar-ir-schema/src/index.js';
import { enforceDriverGate } from './driver-gate.js';

// ---------------------------------------------------------------------------
// N-259 — in on-chain mode six of the seven SDK ANF interpreters answered
// `false` from `checkMultiSig` for EVERY input, a valid 2-of-3 included,
// because they did not model `array_literal` (TS returned undefined, Go nil,
// Rust a hard-coded false, Python / Ruby / Java never built a list), so
// `checkMultiSig` never saw a signature list. Zig built the lists but, like the
// others' dead code, walked them left to right with no encoding gates and no
// NULLFAIL. The compiled script is a bare OP_CHECKMULTISIG over
// `0 <s1> <s2> 2 <pk1> <pk2> <pk3> 3`: `Spend` examines s2 against pk3 first,
// walks both lists toward s1 / pk1, ABORTS on a malformed encoding of a pair
// it examines (as OP_CHECKSIG does, N-197), and stops once fewer keys remain
// than signatures, so a key it never reaches is never encoding-checked.
//
// One vector file (`checkmultisig-onchain/vectors.json`) is replayed through:
//   - the ORACLE: the probe compiled and run on @bsv/sdk `Spend.validate()`
//     (`ScriptExecutionContract.execute`, version-1 rules). The vectors'
//     sighash IS the digest Spend computes for this probe in that context (the
//     first describe recomputes it), so every signature in the file verifies
//     under Spend and Spend adjudicates success, false and abort directly;
//   - the TS SDK reference `executeOnChainAuthoritative`, in-process;
//   - the six per-SDK drivers (`--mode=on-chain`).
//
// NULLFAIL (BIP146, user decision R73.2, N-198): a failed OP_CHECKMULTISIG
// with ANY non-empty signature aborts the script on a BSV node. `Spend` has no
// NULLFAIL and pushes false, so for the `nullfail` vectors Spend is NOT the
// oracle; its describe pins that divergence instead of adjudicating it.
//
// What this proves: a valid 2-of-3 (all three signer pairs) succeeds in every
// SDK on-chain interpreter as it does under Spend; a wrong or out-of-order
// signature makes it fail (abort, as a node does under NULLFAIL); the encoding
// gates fire on exactly the pairs Spend examines, in Spend's order (a malformed
// pk3 aborts, a malformed pk1 that is never reached does not; a bare-DER
// second signature with no sighash-type byte aborts, N-255); and an all-empty
// failing multisig pushes false and lets the other arm carry the spend.
//
// What this does not prove: (a) NULLFAIL against a node — no engine here
// enforces it independently of the interpreters; (b) thresholds other than
// 2-of-3, or N > M (the compiler refuses it; each interpreter aborts as Spend
// does, untested here); (c) the runar-testing TestContract interpreter, which
// is not an SDK interpreter; (d) the value of the sighash-type byte, which
// neither Spend's encoding gate nor the interpreters check.
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const DRIVERS_DIR = join(__dirname, 'drivers');
const ANF_PATH = join(__dirname, 'programs', 'checkmultisig-or-probe.anf.json');
const SOURCE_PATH = join(__dirname, 'programs', 'CheckMultiSigOrProbe.runar.ts');
const VECTORS_PATH = join(__dirname, 'checkmultisig-onchain', 'vectors.json');

/** The ANF binding of `checkMultiSig(...)` — the Rust tier's abort binding. */
const MULTISIG_BINDING = 't7';
/** The ANF binding of the final `assert(...)`. */
const ASSERT_BINDING = 't13';
const SHARED_DIAGNOSTIC = /OP_CHECKMULTISIG aborts/;

type Outcome = 'succeeds' | 'false' | 'assert' | 'aborts';
interface Vector {
  name: string;
  s1: string; s2: string; pk1: string; pk2: string; pk3: string; sigB: string;
  outcome: Outcome;
  /** Aborts on a node under NULLFAIL; Spend (no NULLFAIL) does not. */
  nullfail?: boolean;
  reason?: string;
}
interface Vectors { sighash: string; pubB: string; cases: Vector[] }

const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as Vectors;
const anf = JSON.parse(readFileSync(ANF_PATH, 'utf8')) as ANFProgram;
const SUCCESS = { state: {}, dataOutputs: [], rawOutputs: [] };
const script = ScriptExecutionContract.fromSource(
  readFileSync(SOURCE_PATH, 'utf8'), {}, 'CheckMultiSigOrProbe.runar.ts',
);

function argsFor(v: Vector): Record<string, unknown> {
  return { s1: v.s1, s2: v.s2, pk1: v.pk1, pk2: v.pk2, pk3: v.pk3, sigB: v.sigB, pubB: vectors.pubB };
}

function verifies(sigHex: string, pkHex: string): boolean {
  const der = Buffer.from(sigHex, 'hex').subarray(0, -1);
  // Raw ECDSA over the 32-byte digest, as OP_CHECKMULTISIG verifies it
  // (`PublicKey.verify` would sha256 the message again).
  return ECDSA.verify(
    new BigNumber(vectors.sighash, 16), Signature.fromDER(Array.from(der)), PublicKey.fromString(pkHex),
  );
}

describe('N-259: the vectors and the probe are what they claim', () => {
  it('the vectors carry the sighash Spend computes for the compiled probe', () => {
    const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
    const preimage = TransactionSignature.formatBytes({
      ...CONSENSUS_SPEND_CONTEXT, otherInputs: [], outputs: [],
      subscript: LockingScript.fromHex(script.scriptHex), scope,
    });
    expect(Buffer.from(Hash.hash256(Array.from(preimage))).toString('hex')).toBe(vectors.sighash);
  });

  it('the probe ANF feeds two array_literals into checkMultiSig, ORed with checkSig', () => {
    const unlock = anf.methods.find(m => m.name === 'unlock')!;
    const ms = unlock.body.find(b => b.name === MULTISIG_BINDING)!;
    expect(ms.value).toMatchObject({ kind: 'call', func: 'checkMultiSig', args: ['t2', 't6'] });
    expect(unlock.body.find(b => b.name === 't2')!.value).toMatchObject({ kind: 'array_literal', elements: ['t0', 't1'] });
    expect(unlock.body.find(b => b.name === 't6')!.value).toMatchObject({ kind: 'array_literal', elements: ['t3', 't4', 't5'] });
    expect(unlock.body.find(b => b.value.kind === 'if')!.value).toMatchObject({ cond: MULTISIG_BINDING });
    expect(unlock.body.find(b => b.name === ASSERT_BINDING)!.value).toMatchObject({ kind: 'assert' });
  });

  it('every "succeeds" vector has an empty sigB, so only the multisig can satisfy the assert', () => {
    const ok = vectors.cases.filter(c => c.outcome === 'succeeds');
    expect(ok.length).toBeGreaterThanOrEqual(3);
    for (const v of ok) expect(v.sigB).toBe('');
  });

  it('the signer pairs of the valid vectors verify against their keys; the NULLFAIL ones are well-formed', () => {
    const [v12, v13, v23] = vectors.cases;
    expect([verifies(v12!.s1, v12!.pk1), verifies(v12!.s2, v12!.pk2)]).toEqual([true, true]);
    expect([verifies(v13!.s1, v13!.pk1), verifies(v13!.s2, v13!.pk3)]).toEqual([true, true]);
    expect([verifies(v23!.s1, v23!.pk2), verifies(v23!.s2, v23!.pk3)]).toEqual([true, true]);
    for (const v of vectors.cases.filter(c => c.nullfail)) {
      expect(v.outcome).toBe('aborts');
      expect(v.s1.length + v.s2.length).toBeGreaterThan(0);
    }
  });
});

describe('N-259 oracle: Spend.validate() on the compiled probe', () => {
  for (const v of vectors.cases) {
    // A `nullfail` vector: Spend pushes false (no NULLFAIL), so the outcome is
    // whatever sigB makes of it. That is Spend's verdict, not a node's.
    const spend: Outcome = v.nullfail ? (v.sigB === '' ? 'assert' : 'false') : v.outcome;
    it(`${v.name} → ${spend}`, () => {
      const r = script.execute('unlock', [v.s1, v.s2, v.pk1, v.pk2, v.pk3, v.sigB, vectors.pubB]);
      if (spend === 'succeeds' || spend === 'false') {
        expect(r).toEqual({ success: true });
      } else if (spend === 'aborts') {
        expect(r.success).toBe(false);
        // Spend's encoding gates throw their own message from inside OP_CHECKMULTISIG.
        expect(r.error).toMatch(/signature format is invalid|low S value|public key is in an unknown format/i);
      } else {
        expect(r.success).toBe(false);
        expect(r.error ?? '').not.toMatch(/encoding/);
      }
    });
  }
});

describe('N-259: TS SDK executeOnChainAuthoritative', () => {
  for (const v of vectors.cases) {
    it(`${v.name} → ${v.outcome}`, () => {
      const run = () => executeOnChainAuthoritative(
        anf, 'unlock', {}, argsFor(v), [], { sighash: vectors.sighash },
      );
      if (v.outcome === 'aborts') {
        let err: unknown;
        try { run(); } catch (e) { err = e; }
        expect(err).toBeInstanceOf(Error);
        expect(err).not.toBeInstanceOf(AssertionFailureError);
        expect((err as Error).message).toMatch(SHARED_DIAGNOSTIC);
        expect((err as Error).message).toContain(v.reason!);
      } else if (v.outcome === 'assert') {
        expect(run).toThrow(AssertionFailureError);
      } else {
        expect(run().state).toEqual({});
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
enforceDriverGate('N-259 on-chain checkMultiSig', driverConfigs.filter(c => !isDriverAvailable(c)), process.env);

const inputDir = mkdtempSync(join(tmpdir(), 'runar-n259-'));

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
  describe.skipIf(!isDriverAvailable(cfg))(`N-259: ${cfg.name} SDK on-chain driver`, () => {
    vectors.cases.forEach((v, i) => {
      it(`${v.name} → ${v.outcome}`, () => {
        const argv = [...(cfg.prefix ?? []), cfg.binary, '--mode=on-chain', writeInput(v, i)];
        const r = spawnSync(argv[0]!, argv.slice(1), {
          cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'],
        });
        const stdout = (r.stdout ?? '').trim();
        const stderr = r.stderr ?? '';
        if (v.outcome === 'succeeds' || v.outcome === 'false') {
          expect(r.status, `${cfg.name} exited ${r.status}: ${stderr}`).toBe(0);
          expect(JSON.parse(stdout)).toEqual(SUCCESS);
          return;
        }
        if (v.outcome === 'assert') {
          expect(r.status, stderr).toBe(0);
          expect(JSON.parse(stdout)).toEqual({
            error: 'AssertionFailureError', methodName: 'unlock', bindingName: ASSERT_BINDING,
          });
          return;
        }
        if (cfg.abort === 'assert-at-call') {
          expect(r.status, stderr).toBe(0);
          // At the checkMultiSig call binding, NOT the final assert (t13).
          expect(JSON.parse(stdout)).toEqual({
            error: 'AssertionFailureError', methodName: 'unlock', bindingName: MULTISIG_BINDING,
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
