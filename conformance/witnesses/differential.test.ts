import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  runDifferentialExecution,
  isWitnessSignMarker,
  type WitnessArg,
  type WitnessSignMarker,
} from '../../packages/runar-testing/src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(__dirname, '..', 'tests');

/** Decode a method-argument literal: bigint ("27n"), boolean, or bytes ("0x…"). */
function decodeArg(v: unknown): WitnessArg | WitnessSignMarker {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    if (v.startsWith('0x')) return Uint8Array.from(Buffer.from(v.slice(2), 'hex'));
  }
  // `{"signWith": "<key>"}` — the oracle fills this with a REAL secp256k1
  // signature over ScriptVM's synthetic BIP-143 context. Without it no
  // checkSig contract could carry a witness at all: a literal signature fails
  // the VM's real OP_CHECKSIG while the interpreter mocks it, so the oracle
  // would report a harness artefact as a divergence.
  if (isWitnessSignMarker(v)) return v;
  throw new Error(`unencodable witness arg: ${JSON.stringify(v)}`);
}

/**
 * Decode a constructor-argument literal. The compiler + interpreter accept
 * bigint | boolean | string(hex), so byte strings become a bare hex string
 * (no 0x prefix) rather than a Uint8Array.
 *
 * DIALECT WARNING — stricter than `scalar()` in
 * witnesses/real-crypto-execution.test.ts. These specs (`witnesses/*.json`)
 * REQUIRE an explicit `0x` prefix for bytes and throw on a bare string; the
 * real-crypto specs (`witnesses/real-crypto/*.json`) accept bare hex. The two
 * directories are disjoint, so no file is decoded both ways — but a spec copied
 * between them will throw here (or silently decode as bytes there).
 */
function decodeCtor(v: unknown): bigint | boolean | string {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'string') {
    if (/^-?\d+n$/.test(v)) return BigInt(v.slice(0, -1));
    if (v.startsWith('0x')) return v.slice(2);
  }
  throw new Error(`unencodable constructor arg: ${JSON.stringify(v)}`);
}

const NON_SPEC_JSON = new Set(['coverage-ledger.json']);
const specFiles = readdirSync(__dirname).filter(
  (f) => f.endsWith('.json') && !NON_SPEC_JSON.has(f),
);

describe('per-fixture differential execution (source vs script, fold-ON)', () => {
  for (const specFile of specFiles) {
    const spec = JSON.parse(readFileSync(join(__dirname, specFile), 'utf-8'));
    const fixtureDir = join(TESTS_DIR, spec.fixture);
    const srcCfg = JSON.parse(readFileSync(join(fixtureDir, 'source.json'), 'utf-8'));
    // Resolve the .runar.ts source path from source.json's `sources` map (paths
    // are relative to the fixture's directory), falling back to a bare `path`.
    const tsRel: string | undefined = srcCfg.sources?.['.runar.ts'] ?? srcCfg.path;
    if (!tsRel) throw new Error(`no .runar.ts source in ${spec.fixture}/source.json`);
    const srcPath = resolve(fixtureDir, tsRel);
    const source = readFileSync(srcPath, 'utf-8');
    const fileName = srcPath.split('/').pop()!;

    const ctor: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(spec.constructorArgs ?? {})) ctor[k] = decodeCtor(val);

    describe(spec.fixture, () => {
      for (const s of spec.spends) {
        it(`${s.method}(${s.args.join(',')}) → ${s.expect} [${s.note ?? ''}]`, () => {
          const r = runDifferentialExecution({
            source,
            fileName,
            method: s.method,
            args: (s.args as unknown[]).map(decodeArg),
            constructorArgs: ctor,
          });
          // 1. Interpreter and script engine agree on accept/reject.
          expect(
            r.agrees,
            `DIVERGENCE interpreter=${r.interpreterAccepted} vm=${r.vmAccepted} interpErr=${r.interpreterError} vmErr=${r.vmError} locking=${r.lockingHex} witness=${r.witnessHex}`,
          ).toBe(true);
          // 2. And they agree with the declared expectation.
          expect(r.vmAccepted).toBe(s.expect === 'accept');
        });
      }
    });
  }
});
