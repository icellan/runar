/**
 * R-250 (CL-DOC-006): "NOT handled: P == -Q" sat directly above code that
 * handles it, in the Ruby and Java P-256/P-384 modules.
 *
 * Both files explain the fix a few dozen lines further down, under "THE THIRD
 * CASE, P == -Q": px == qx with py != qy returns the all-zero blob this codegen
 * uses for the point at infinity, which the on-curve gate then rejects. The
 * stale line above it predated that fix, and it is the dangerous kind of stale:
 * a reader auditing the incomplete-addition class would have taken the file's
 * word that the case was open.
 *
 * Absent from the Go reference, so it was introduced during the ports.
 *
 * This test fails if the claim comes back anywhere, and asserts the explanation
 * that replaces it is still present — so deleting both is not a way to pass.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const EC_MODULES = [
  'compilers/ruby/lib/runar_compiler/codegen/p256_p384.rb',
  'compilers/java/src/main/java/runar/compiler/codegen/P256P384.java',
];

describe('R-250: no EC module claims P == -Q is unhandled', () => {
  it.each(EC_MODULES)('%s', (rel) => {
    const src = readFileSync(join(ROOT, rel), 'utf8');

    expect(
      src.includes('NOT handled: P == -Q'),
      'the stale claim is back; the case IS handled below it',
    ).toBe(false);

    expect(
      src.includes('THE THIRD CASE, P == -Q'),
      'the explanation of how P == -Q is handled has gone missing',
    ).toBe(true);
  });
});
