/**
 * N-316: matchesArtifact must treat codeSepIndexSlots and codePartLenSlots as
 * variable script elements even when `constructorSlots` is empty.
 *
 * Replays the shared cross-tier fixture conformance/sdk-matches-artifact/
 * fixtures.json (also replayed by the Go, Rust, Python, Zig, Ruby and Java
 * SDKs). Its first artifact is the real compiler output for a stateful
 * contract with no constructor args and a ByteString state field, so the
 * only slots are a codeSepIndex slot (baked OP_0 -> OP_1) and a code-part
 * length pin.
 *
 * Proves: an honest deployment (SDK-built, any state) matches its own artifact
 * and a script differing in one code byte before/after the slot does not.
 * Does NOT prove: on-chain spendability, nor other slot layouts than the ones
 * in the fixture.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchesArtifact } from '../script-utils.js';
import type { RunarArtifact } from '../types.js';

const fixture = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-matches-artifact/fixtures.json'),
    'utf8',
  ),
) as { cases: { name: string; artifact: unknown; script_hex: string; expected: boolean }[] };

describe('N-316: matchesArtifact with only codeSepIndex / codePartLen slots', () => {
  for (const c of fixture.cases) {
    it(c.name, () => {
      expect(matchesArtifact(c.artifact as RunarArtifact, c.script_hex)).toBe(c.expected);
    });
  }
});
