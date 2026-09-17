/**
 * Remaining-policy pin for the 21 Go-only bn254 / KoalaBear builtins
 * that have no executing coverage in the conformance goldens.
 *
 * Policy exclusion from the 7-tier hex matrix is not evidence they
 * evaluate correctly (that gap hid `pow`, the Go-surface hash drop, and
 * the Move countdown). This file does not invent a 21-row execution
 * oracle; it makes the uncovered names a ratchet: dropping one from the
 * list without adding an executing test fails here.
 *
 * `EXECUTING` names are those already driven through the go-sdk
 * interpreter in this repo. Everything else must stay in `REMAINING`
 * with a reason.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Builtins scoped to the Go tier by CLAUDE.md. */
const GO_ONLY = [
  'kbFieldAdd', 'kbFieldSub', 'kbFieldMul', 'kbFieldInv',
  'kbExt4Mul0', 'kbExt4Mul1', 'kbExt4Mul2', 'kbExt4Mul3',
  'kbExt4Inv0', 'kbExt4Inv1', 'kbExt4Inv2', 'kbExt4Inv3',
  'bn254FieldAdd', 'bn254FieldSub', 'bn254FieldMul', 'bn254FieldInv', 'bn254FieldNeg',
  'bn254G1Add', 'bn254G1ScalarMul', 'bn254G1Negate', 'bn254G1OnCurve',
] as const;

const EXECUTING = new Set<string>([
  'bn254G1OnCurve',
  'bn254G1Negate',
]);

const REMAINING_REASON =
  'Go-only by project policy; no spend-oracle executing coverage yet. Listed so dropping the name is loud.';

describe('Go-only builtin executing-coverage ratchet', () => {
  it('lists exactly 21 names', () => {
    expect(GO_ONLY.length).toBe(21);
  });

  it('every name is either executing or remaining — no silent third state', () => {
    const leftover: string[] = [];
    for (const name of GO_ONLY) {
      if (!EXECUTING.has(name)) leftover.push(name);
    }
    expect(leftover.length, leftover.join(', ')).toBe(21 - EXECUTING.size);
    for (const name of leftover) {
      expect(REMAINING_REASON.length).toBeGreaterThan(10);
      expect(name.startsWith('kb') || name.startsWith('bn254')).toBe(true);
    }
  });

  it('EXECUTING names actually appear in an execution test file', () => {
    const execFiles: string[] = [];
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory() && e.name !== 'node_modules') walk(p);
        else if (/execution_test\.go$/.test(e.name) || /r141_.*\.go$/.test(e.name)) {
          execFiles.push(p);
        }
      }
    };
    walk(join(ROOT, 'conformance'));
    walk(join(ROOT, 'compilers/go/codegen'));
    const blob = execFiles.map((f) => readFileSync(f, 'utf8')).join('\n');
    for (const name of EXECUTING) {
      expect(blob, `${name} claimed executing but not in execution tests`).toContain(name);
    }
  });
});
