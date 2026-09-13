import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * R-196 / CL-DOC-007 — the documented pipeline skipped a pass that exists.
 *
 * CLAUDE.md and packages/runar-compiler/README.md both listed six passes:
 * parse, validate, typecheck, ANF-lower, stack-lower, emit. `index.ts` runs a
 * seventh between typecheck and ANF lowering — `03b-expand-fixed-arrays.ts` —
 * with its own diagnostics, its own conformance fixtures, and a port in all
 * seven tiers. The same omission was reported independently by the Go and Rust
 * pipeline reviewers, which is what a missing pass in the governing document
 * costs: three people counted the passes and got the same wrong number.
 *
 * This pins the list against the directory. A new `NN-*.ts` pass file that
 * nobody documents fails here, which is the failure mode the finding
 * describes.
 */

const REPO = resolve(__dirname, '../../../..');
const PASSES_DIR = resolve(REPO, 'packages/runar-compiler/src/passes');

/** Top-level pipeline pass files, by their `NN[x]-` prefix. */
function pipelinePassFiles(): string[] {
  return readdirSync(PASSES_DIR)
    .filter((f) => /^\d{2}[a-z]?-[a-z0-9-]+\.ts$/.test(f))
    // 01-parse-<format>.ts are per-surface parsers behind pass 1's dispatch,
    // not passes of their own.
    .filter((f) => !/^01-parse-/.test(f))
    .sort();
}

describe('R-196 the documented pipeline matches the passes that exist', () => {
  it('finds the pass files (an empty sweep would pass vacuously)', () => {
    const files = pipelinePassFiles();
    expect(files.length).toBeGreaterThanOrEqual(6);
    expect(files).toContain('03b-expand-fixed-arrays.ts');
  });

  for (const doc of ['CLAUDE.md', 'packages/runar-compiler/README.md']) {
    it(`${doc} mentions every pipeline pass`, () => {
      const text = readFileSync(resolve(REPO, doc), 'utf-8');
      const missing = pipelinePassFiles().filter((f) => {
        const stem = f.replace(/\.ts$/, '');
        // Either the file name or the exported function name counts as
        // documenting it — README shows the API, CLAUDE.md the file list.
        const bare = stem.replace(/^\d{2}[a-z]?-/, '');
        const camel = bare.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        // The file name, the hyphenated pass name, or the exported function
        // all count — CLAUDE.md lists files, the README shows the API and a
        // prose list of the pass names.
        return !text.includes(stem) && !text.includes(camel)
          && !new RegExp(bare.replace(/-/g, '[- ]'), 'i').test(text);
      });
      expect(
        missing,
        `${doc} documents the pipeline but omits ${missing.join(', ')} — ` +
          `a reviewer counting passes from this document gets the wrong number, ` +
          `which is how R-196 was found three times independently.`,
      ).toEqual([]);
    });
  }
});
