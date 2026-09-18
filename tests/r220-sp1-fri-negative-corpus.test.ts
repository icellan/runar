/**
 * R-220 (CL-GAP-070) — the SP1 FRI negative corpus and the audit note that
 * describes it.
 *
 * The finding, quoting `docs/audit/2026-08-go-only-crypto-oracles.md`:
 * the Merkle scheme and the FRI folding rule are self-graded, and "all eight
 * [corruption] directories contain only a `.gitkeep`" so "the verifier's
 * rejection paths therefore have no fixtures at all".
 *
 * Both halves are now out of date, and this file is what keeps them from
 * going out of date again — the audit note is prose, and prose does not fail
 * a build when the tree moves underneath it (the mistake R-218 caught in the
 * decompiler README).
 *
 * Corpus: seven of the eight directories carry real bytes, landed by
 * `7713e1df` / `9966124c`, and `compilers/go/codegen/sp1_fri_negative_test.go`
 * drives each one through the reference verifier asserting both THAT it is
 * rejected and WHERE. The eighth, `bad_vk`, has no fixture because one cannot
 * exist at the PoC parameter set: `minimal-guest/proof.postcard` is a raw
 * Plonky3 `p3_uni_stark::Proof` with no SP1 wrapper and therefore no verifying
 * key, which is why `SP1VKeyHashByteSize` is pinned to 0. Its README says so
 * at length and `TestSp1FriVerifier_BadVkCorruptionIsDocumentedAbsent` gates
 * it. That is a documented impossibility, not a hole.
 *
 * Folding rule: measured, not argued. `minimal-guest/proof.postcard` is real
 * Plonky3 output, so the repo's independent Go verifier accepting it end to
 * end IS a cross-implementation check of the fold. Perturbing `foldRow` to use
 * `KbTwoAdicGenerator(logHeight)` instead of `logHeight + logArity` makes
 * `TestVerifyMinimalGuest` fail with `query 0 final_poly mismatch`. The
 * standalone colinearity VECTORS are still generator-authored — that part of
 * the finding stands — but the rule itself is anchored upstream.
 *
 * One real hole the measurement exposed, which the finding did not name: the
 * pinned config sets `max_log_arity: 1`, so every fold is arity-2 and
 * `reverseSliceIndexBits` is a no-op on two elements. Deleting that call
 * changes nothing and every SP1 FRI test still passes. The bit-reversal is
 * unexercised at this parameter set and will only be graded when a fixture
 * with `max_log_arity > 1` lands.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const corruptionsDir = join(repoRoot, 'tests', 'vectors', 'sp1', 'fri', 'corruptions');
const goTestPath = join(repoRoot, 'compilers', 'go', 'codegen', 'sp1_fri_negative_test.go');
const auditNotePath = join(repoRoot, 'docs', 'audit', '2026-08-go-only-crypto-oracles.md');

/** Directory deliberately carrying no fixture; see its README. */
const DOCUMENTED_ABSENT = 'bad_vk';

const corruptionDirs = readdirSync(corruptionsDir, { withFileTypes: true })
  .filter(e => e.isDirectory())
  .map(e => e.name)
  .sort();

describe('SP1 FRI corruption corpus', () => {
  it('has the eight directories the corruption matrix names (anti-vacuity)', () => {
    expect(corruptionDirs).toEqual([
      'all_zeros', 'bad_final_poly', 'bad_folding', 'bad_merkle',
      'bad_vk', 'truncated', 'wrong_program', 'wrong_public_values',
    ]);
  });

  it.each(corruptionDirs.filter(d => d !== DOCUMENTED_ABSENT))(
    '%s carries real fixture bytes, not a placeholder',
    dir => {
      const proof = join(corruptionsDir, dir, 'proof.postcard');
      expect(existsSync(proof), `${dir}/proof.postcard is missing`).toBe(true);
      expect(statSync(proof).size).toBeGreaterThan(0);
      expect(existsSync(join(corruptionsDir, dir, 'public_values.hex'))).toBe(true);
      expect(existsSync(join(corruptionsDir, dir, '.gitkeep'))).toBe(false);
    },
  );

  it('bad_vk carries an explanation instead of inert bytes', () => {
    expect(existsSync(join(corruptionsDir, DOCUMENTED_ABSENT, 'proof.postcard'))).toBe(false);
    const readme = readFileSync(join(corruptionsDir, DOCUMENTED_ABSENT, 'README.md'), 'utf8');
    expect(readme).toMatch(/NOT GENERATED/);
    expect(readme).toMatch(/SP1VKeyHashByteSize/);
  });

  it('every generated directory is driven by the Go negative test', () => {
    // A fixture nobody loads grades nothing. The Go suite's case matrix is the
    // list of directories it actually opens.
    const goSource = readFileSync(goTestPath, 'utf8');
    const driven = new Set(
      [...goSource.matchAll(/dir:\s*"([a-z_]+)"/g)].map(m => m[1]!),
    );
    expect(driven.size, 'parsed no cases out of the Go test — the matcher is stale')
      .toBeGreaterThanOrEqual(7);
    const undriven = corruptionDirs
      .filter(d => d !== DOCUMENTED_ABSENT && !driven.has(d));
    expect(undriven).toEqual([]);
  });
});

describe('the audit note matches the tree it describes', () => {
  const note = readFileSync(auditNotePath, 'utf8');

  it('is the note this test was written against (anti-vacuity)', () => {
    expect(note).toMatch(/Residual risk/);
  });

  it('no longer claims the negative corpus is empty', () => {
    // Kept as an absence check rather than a phrasing check: the superseded
    // sentences are gone from the document entirely, so a future edit that
    // reinstates either of them fails here. (R-218: a document must not carry
    // the figures it supersedes, or its own guard cannot tell them apart.)
    expect(note).not.toMatch(/contain only a `?\.gitkeep`?/);
    expect(note).not.toMatch(/no fixtures at all/);
    expect(note).not.toMatch(/the negative corpus is missing/);
  });

  it('no longer calls the FRI folding rule ungraded without saying what grades it', () => {
    expect(note).toMatch(/minimal-guest/);
  });
});
