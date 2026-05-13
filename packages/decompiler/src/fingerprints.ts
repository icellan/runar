/**
 * Fingerprint database — loader and matcher input.
 *
 * The DB is generated at test time by `scripts/build-fingerprints.ts` and
 * checked into the repo as `fingerprints.json`. It maps EC builtin templates
 * (large opcode sequences with stable shapes — e.g. `ecMul` is ~1500 bytes
 * of Jacobian arithmetic) to their builtin name and arity, so the matcher
 * can replace a span of raw opcodes with a single `BuiltinCall` marker
 * before symbolic execution.
 *
 * Single-opcode builtins (hash160 / sha256 / ripemd160 / checkSig / …) are
 * deliberately NOT in this DB; the lifter recovers them from operand
 * provenance + type inference.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import type { Fingerprint, FingerprintDB } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/** Resolve the default DB path relative to the package root. */
function defaultDbPath(): string {
  // src/fingerprints.ts → ../fingerprints.json (built or source layout)
  return resolve(__dirname, '..', 'fingerprints.json');
}

export function loadFingerprints(path?: string): FingerprintDB {
  const p = path ?? defaultDbPath();
  try {
    const raw = readFileSync(p, 'utf8');
    return JSON.parse(raw) as FingerprintDB;
  } catch {
    return emptyDB();
  }
}

export function emptyDB(): FingerprintDB {
  return {
    compilerVersion: 'unknown',
    generatedAt: new Date(0).toISOString(),
    entries: [],
  };
}

/** Group entries by template length descending — longest-first matching. */
export function entriesByLengthDesc(db: FingerprintDB): Fingerprint[] {
  return [...db.entries].sort((a, b) => b.length - a.length);
}
