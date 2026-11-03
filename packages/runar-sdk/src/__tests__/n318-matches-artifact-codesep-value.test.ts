/**
 * N-318: matchesArtifact must check the VALUE at every codeSepIndex slot.
 *
 * Deploy bakes a deterministic number there: codeSepIndex plus the growth of
 * every constructor slot (and every earlier codeSep slot) located before
 * codeSepIndex. The matcher used to skip whatever element sat at the slot, so
 * a lookalike script carrying a forged separator index matched as genuine.
 *
 * Replays the shared cross-tier vector conformance/sdk-matches-artifact/
 * codesep.json (also replayed by the Go, Rust, Python, Zig, Ruby and Java
 * SDKs): honest = RunarContract.getLockingScript() for a real TS-compiled
 * stateful artifact (two codeSep slots, a constructor slot between them) and
 * a synthetic artifact whose baked values depend on a variable-length
 * constructor arg; forged = the same script with only a codeSep slot
 * element replaced (OP_0, OP_N off by one, non-minimal pushes, the unshifted
 * template index), code-part length pins re-patched.
 *
 * Proves: honest deployments match whatever the constructor-arg width, and a
 * script differing only in the number pushed at a codeSep slot does not.
 * Does NOT prove: on-chain spendability of the honest scripts, nor anything
 * about artifacts whose codeSepIndex points past a constructor slot that the
 * compiler never emits beyond the synthetic layout here.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { matchesArtifact } from '../script-utils.js';
import type { RunarArtifact } from '../types.js';

const fixture = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-matches-artifact/codesep.json'),
    'utf8',
  ),
) as {
  artifacts: Record<string, unknown>;
  cases: { name: string; artifact: string; script_hex: string; expected: boolean }[];
};

describe('N-318: matchesArtifact checks the value baked at codeSepIndex slots', () => {
  for (const c of fixture.cases) {
    it(c.name, () => {
      expect(matchesArtifact(fixture.artifacts[c.artifact] as RunarArtifact, c.script_hex)).toBe(c.expected);
    });
  }
});
