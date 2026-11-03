import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * N-367 — the header comment of every tier's const-reassignment helper names
 * the surfaces the checker is actually wired to: `.runar.ts`, and since N-344
 * `.runar.rs` and `.runar.zig`. After N-344 only the TS header was updated; the
 * other six still said "`.runar.ts` only".
 *
 * What this proves: each helper's leading comment mentions all three surfaces
 * and carries no ".runar.ts only" style restriction.
 * What it does NOT prove: that the comment matches the call sites (that was
 * checked by hand from each tier's parser dispatch); the checker's behaviour is
 * covered by n342/n344 parity tests.
 */
const ROOT = resolve(__dirname, '..', '..');
const HELPERS = [
  'packages/runar-compiler/src/passes/const-reassign.ts',
  'compilers/go/frontend/const_reassign.go',
  'compilers/rust/src/frontend/const_reassign.rs',
  'compilers/python/runar_compiler/frontend/const_reassign.py',
  'compilers/ruby/lib/runar_compiler/frontend/const_reassign.rb',
  'compilers/zig/src/passes/const_reassign.zig',
  'compilers/java/src/main/java/runar/compiler/frontend/ConstReassign.java',
];

/** The leading comment block: everything before the first `import`/`use`/`require`/`const std`/`package`-body code line. */
function header(text: string): string {
  const marker = text.indexOf('because it is a constant');
  // The N-342 header always precedes the shared message function.
  return text.slice(0, marker);
}

describe('N-367 const-reassign helper header scope', () => {
  for (const rel of HELPERS) {
    it(`${rel} names .runar.ts, .runar.rs and .runar.zig`, () => {
      const h = header(readFileSync(join(ROOT, rel), 'utf8'));
      expect(h).toContain('.runar.ts');
      expect(h).toContain('.runar.rs');
      expect(h).toContain('.runar.zig');
      expect(h).not.toMatch(/\.runar\.ts(`|\}|\+|``)?\s+(parse result\s+)?only/);
      expect(h).not.toMatch(/ts\+?`?\s+parse result only/);
    });
  }
});
