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
import type { Fingerprint, FingerprintDB } from './types.js';
import { packageDataPath } from './package-data.js';

/**
 * Load the fingerprint DB (default: `<package root>/fingerprints.json`).
 * A missing or unparseable file throws: an empty DB would silently
 * disable fingerprint-assisted recovery while decompilation still
 * reports success.
 */
export function loadFingerprints(path?: string): FingerprintDB {
  const p = path ?? packageDataPath('fingerprints.json');
  try {
    return JSON.parse(readFileSync(p, 'utf8')) as FingerprintDB;
  } catch (e) {
    throw new Error(`runar-decompiler: cannot load fingerprint DB ${p}: ${(e as Error).message}`);
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
