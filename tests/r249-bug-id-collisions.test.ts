/**
 * R-249 (CL-DOC-005): "BUG-011" names two unrelated fixes — the Rabin
 * digest-encoding normalisation and the SLH-DSA exact signature-length guard —
 * in every tier. 65 references across 32 files, none saying which one it means.
 *
 * The references are not renamed: they are historical, they appear in commit
 * messages and in audit reports outside this repository, and one is in
 * runar-verification/, which this work does not touch. Rewriting them would
 * break the link between the code and the audit trail that named it.
 *
 * Instead the collision is recorded once, where a search lands:
 * docs/audit/bug-id-collisions.md. This test keeps that note honest — it must
 * exist, it must describe both meanings, and it must name a file from each side
 * so a reader can tell them apart.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const NOTE = join(ROOT, 'docs', 'audit', 'bug-id-collisions.md');

describe('R-249: the BUG-011 collision is recorded', () => {
  it('has a note that distinguishes both meanings', () => {
    expect(existsSync(NOTE), `${NOTE} is missing`).toBe(true);
    const text = readFileSync(NOTE, 'utf8');

    expect(text).toContain('BUG-011');
    // Both subjects, named.
    expect(text).toMatch(/Rabin/);
    expect(text).toMatch(/SLH-DSA/);
    // And a file from each side, so "which one is this?" is answerable.
    expect(text).toContain('rabin-codegen.ts');
    expect(text).toContain('slh-dsa-codegen.ts');
  });

  it('still describes a real collision', () => {
    // If BUG-011 ever stops naming two things, this note should be revisited
    // rather than left asserting a collision that no longer exists.
    const rabin = readFileSync(
      join(ROOT, 'packages/runar-compiler/src/passes/rabin-codegen.ts'),
      'utf8',
    );
    const slhDsa = readFileSync(
      join(ROOT, 'packages/runar-compiler/src/passes/slh-dsa-codegen.ts'),
      'utf8',
    );

    expect(rabin, 'the Rabin side no longer mentions BUG-011').toContain('BUG-011');
    expect(slhDsa, 'the SLH-DSA side no longer mentions BUG-011').toContain('BUG-011');
  });
});
