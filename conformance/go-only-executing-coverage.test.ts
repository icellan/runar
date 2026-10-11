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
 * `EXECUTING` maps each covered name to the exact file + test marker that
 * drives it through a real interpreter — the go-sdk engine via
 * `BuildAndExecuteOps`, or `@bsv/sdk`'s `Spend` in the conformance suite.
 * The marker is a test name, not the builtin name: a bare substring match
 * on the builtin name is vacuous (e.g. `bn254G1Add` appears, case-folded
 * differently as `EmitBN254G1Add`, and lowercase verbatim in an unrelated
 * comment, inside compilers/go/codegen/r141_bn254_point_canonicity_test.go
 * — none of that is the dedicated test this file now pins). Renaming or
 * deleting the pinned test — or the file it lives in — fails the third
 * `it` below. Everything else must stay in `REMAINING` with a reason.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
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

interface Coverage {
  /** Path relative to the repo root. */
  file: string;
  /** Exact substring `file` must still contain — a test name, never the builtin name. */
  marker: string;
}

const EXECUTING: Record<string, Coverage> = {
  bn254G1OnCurve: {
    file: 'compilers/go/codegen/r141_bn254_point_canonicity_test.go',
    marker: 'func TestR141_BN254OnCurveRejectsNonCanonicalCoordinates(t *testing.T)',
  },
  bn254G1Negate: {
    file: 'compilers/go/codegen/r141_bn254_point_canonicity_test.go',
    marker: 'func TestR141_BN254ValueBuiltinsAbortOnNonCanonical(t *testing.T)',
  },
  // N-083: F-091 drives the omega-partner pair through @bsv/sdk's Spend in
  // every tier.
  bn254G1Add: {
    file: 'conformance/go-only-parity/go-only-parity.test.ts',
    marker: 'F-091: bn254G1Add omega-partner pair — executed on @bsv/sdk Spend',
  },
  // N-083: the same filename-regex miss that hid F-091 from this ratchet
  // also hid compilers/go/codegen/r119_field_canonicity_test.go, whose
  // koalabear subtest already drives EmitKBFieldAdd/Sub/Mul/Inv through the
  // real go-sdk interpreter via BuildAndExecuteOps.
  kbFieldAdd: {
    file: 'compilers/go/codegen/r119_field_canonicity_test.go',
    marker: 'func TestR119_NonCanonicalScalarOperandRejected(t *testing.T)',
  },
  kbFieldSub: {
    file: 'compilers/go/codegen/r119_field_canonicity_test.go',
    marker: 'func TestR119_NonCanonicalScalarOperandRejected(t *testing.T)',
  },
  kbFieldMul: {
    file: 'compilers/go/codegen/r119_field_canonicity_test.go',
    marker: 'func TestR119_NonCanonicalScalarOperandRejected(t *testing.T)',
  },
  kbFieldInv: {
    file: 'compilers/go/codegen/r119_field_canonicity_test.go',
    marker: 'func TestR119_NonCanonicalScalarOperandRejected(t *testing.T)',
  },
  // N-083: same file, the ext4Mul0/ext4Inv0 koalabear subtest. Variants 1-3
  // are not reached by this test and stay REMAINING.
  kbExt4Mul0: {
    file: 'compilers/go/codegen/r119_field_canonicity_test.go',
    marker: 'func TestR119_Ext4OperandsGated(t *testing.T)',
  },
  kbExt4Inv0: {
    file: 'compilers/go/codegen/r119_field_canonicity_test.go',
    marker: 'func TestR119_Ext4OperandsGated(t *testing.T)',
  },
  // N-156: F-196 drives all five scalar-field entry points' operand
  // canonicity through @bsv/sdk's Spend in every tier.
  bn254FieldAdd: {
    file: 'conformance/go-only-parity/go-only-parity.test.ts',
    marker: 'F-196: bn254Field* operand canonicity — executed on @bsv/sdk Spend',
  },
  bn254FieldSub: {
    file: 'conformance/go-only-parity/go-only-parity.test.ts',
    marker: 'F-196: bn254Field* operand canonicity — executed on @bsv/sdk Spend',
  },
  bn254FieldMul: {
    file: 'conformance/go-only-parity/go-only-parity.test.ts',
    marker: 'F-196: bn254Field* operand canonicity — executed on @bsv/sdk Spend',
  },
  bn254FieldInv: {
    file: 'conformance/go-only-parity/go-only-parity.test.ts',
    marker: 'F-196: bn254Field* operand canonicity — executed on @bsv/sdk Spend',
  },
  bn254FieldNeg: {
    file: 'conformance/go-only-parity/go-only-parity.test.ts',
    marker: 'F-196: bn254Field* operand canonicity — executed on @bsv/sdk Spend',
  },
};

const REMAINING_REASON =
  'Go-only by project policy; no spend-oracle executing coverage yet. Listed so dropping the name is loud.';

describe('Go-only builtin executing-coverage ratchet', () => {
  it('lists exactly 21 names', () => {
    expect(GO_ONLY.length).toBe(21);
  });

  it('every name is either executing or remaining — no silent third state', () => {
    const leftover: string[] = [];
    for (const name of GO_ONLY) {
      if (!(name in EXECUTING)) leftover.push(name);
    }
    expect(leftover.length, leftover.join(', ')).toBe(21 - Object.keys(EXECUTING).length);
    for (const name of leftover) {
      expect(REMAINING_REASON.length).toBeGreaterThan(10);
      expect(name.startsWith('kb') || name.startsWith('bn254')).toBe(true);
    }
  });

  it('EXECUTING names actually appear in their claimed execution test', () => {
    const cache = new Map<string, string>();
    for (const name of Object.keys(EXECUTING)) {
      const { file, marker } = EXECUTING[name]!;
      let content = cache.get(file);
      if (content === undefined) {
        content = readFileSync(join(ROOT, file), 'utf8');
        cache.set(file, content);
      }
      expect(content, `${name} claimed executing but "${marker}" is not in ${file}`).toContain(marker);
    }
  });

  // N-083: F-091 (conformance/go-only-parity/go-only-parity.test.ts) executes
  // bn254G1Add on @bsv/sdk's Spend in every tier. The detector above never
  // saw it before this fix — go-only-parity.test.ts matches neither
  // *execution_test.go nor r141_*.go. The same filename-regex miss also hid
  // compilers/go/codegen/r119_field_canonicity_test.go, which already drives
  // the koalabear EmitKBFieldAdd/Sub/Mul/Inv and EmitKBExt4Mul0/Inv0 emitters
  // through the real go-sdk interpreter via BuildAndExecuteOps.
  it('N-083: bn254G1Add and the koalabear scalar/ext4-0 builtins are executed today', () => {
    expect('bn254G1Add' in EXECUTING, 'bn254G1Add should be EXECUTING — see F-091').toBe(true);
    for (const name of ['kbFieldAdd', 'kbFieldSub', 'kbFieldMul', 'kbFieldInv', 'kbExt4Mul0', 'kbExt4Inv0']) {
      expect(name in EXECUTING, `${name} should be EXECUTING — see r119_field_canonicity_test.go`).toBe(true);
    }
  });

  // N-156: F-196 (conformance/go-only-parity/go-only-parity.test.ts) executes
  // all five bn254Field* scalar-field builtins on @bsv/sdk's Spend in every
  // tier. Same root cause as N-083: the file matches neither
  // *execution_test.go nor r141_*.go, so the detector above never saw it.
  it('N-156: all five bn254Field* builtins are executed today', () => {
    for (const name of ['bn254FieldAdd', 'bn254FieldSub', 'bn254FieldMul', 'bn254FieldInv', 'bn254FieldNeg']) {
      expect(name in EXECUTING, `${name} should be EXECUTING — see F-196`).toBe(true);
    }
  });
});
