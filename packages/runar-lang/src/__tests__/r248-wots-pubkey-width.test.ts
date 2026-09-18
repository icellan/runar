/**
 * R-248 (CL-DOC-004): `verifyWOTS`'s JSDoc said the public key is 32 bytes.
 * The implementation requires 64.
 *
 * `wots-codegen.ts` splits the argument into `pubSeed(32) || pkRoot(32)`, and
 * the interpreter rejects a 32-byte key (there is a test named "rejects
 * wrong-length public key (32 bytes)"). A developer following the JSDoc would
 * have passed a key the compiler then split into halves of the wrong thing.
 *
 * This test ties the prose to the implementation that enforces it, so the two
 * cannot drift apart again silently.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(PKG, '..', '..', '..');

describe('R-248: the verifyWOTS public-key width is documented as implemented', () => {
  it('matches the width the codegen splits', () => {
    const codegen = readFileSync(
      join(REPO, 'packages/runar-compiler/src/passes/wots-codegen.ts'),
      'utf8',
    );
    // The codegen states the width it splits, twice; take it as the authority.
    const enforced = codegen.match(/Split (\d+)-byte pubkey into pubSeed\(32\) and pkRoot\(32\)/);
    expect(enforced, 'the codegen no longer states the pubkey width it splits').not.toBeNull();
    expect(Number(enforced![1])).toBe(64);

    const builtins = readFileSync(join(PKG, 'builtins.ts'), 'utf8');
    const verifyWots = builtins.slice(
      builtins.lastIndexOf('/**', builtins.indexOf('export function verifyWOTS')),
      builtins.indexOf('export function verifyWOTS'),
    );

    // Check the two lines that STATE the width, not any mention of "32 bytes"
    // — the doc legitimately quotes the interpreter test's name, which has
    // "(32 bytes)" in it.
    const sizeLine = verifyWots.match(/Public key size: (\d+) bytes/);
    const paramLine = verifyWots.match(/@param pubkey - WOTS\+ public key \((\d+) bytes/);

    expect(sizeLine, 'the "Public key size" line is gone').not.toBeNull();
    expect(paramLine, 'the "@param pubkey" line is gone').not.toBeNull();
    expect(Number(sizeLine![1]), 'Public key size disagrees with the codegen').toBe(
      Number(enforced![1]),
    );
    expect(Number(paramLine![1]), '@param pubkey disagrees with the codegen').toBe(
      Number(enforced![1]),
    );
  });
});
