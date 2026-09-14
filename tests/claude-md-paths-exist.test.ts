/**
 * Every concrete file path CLAUDE.md names must exist.
 *
 * CLAUDE.md is not prose — it is the checklist a contributor follows. Its
 * "Adding a New ANF Value Kind" section enumerates the ~30 dispatch sites a new
 * IR node has to touch across seven tiers, and a path that silently stops
 * resolving means a site that silently stops getting updated. That is exactly
 * the failure class behind several findings on this branch: a predicate
 * implemented seven times and updated in six.
 *
 * Found by this guard on its first run: five `compilers/ruby/lib/...` paths
 * that had lost the `runar_compiler/` segment — including
 * `codegen/stack.rb` and `frontend/anf_lower.rb`, two of the ANF-kind
 * checklist's own entries.
 *
 * Only CONCRETE paths are checked. Templated (`parser_{format}.rb`), globbed
 * and placeholder (`<fixture>`) spellings are skipped by design — they name a
 * shape, not a file.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Top-level directories a repo-relative path can start with. */
const ROOTS = [
  'packages/', 'compilers/', 'conformance/', 'examples/',
  'docs/', 'spec/', 'integration/', 'tests/', '.github/',
];

function documentedPaths(markdown: string): string[] {
  const found = new Set<string>();
  // Backtick-quoted spans are where this document puts paths.
  for (const m of markdown.matchAll(/`([^`\n]+)`/g)) {
    const raw = m[1]!.trim();
    if (!ROOTS.some(r => raw.startsWith(r))) continue;
    // A shape, not a file.
    if (/[{}<>*]/.test(raw)) continue;
    // Must look like a file (has an extension in its last segment).
    const last = raw.split('/').pop()!;
    if (!/\.[a-z0-9]+$/i.test(last)) continue;
    found.add(raw);
  }
  return [...found].sort();
}

describe('CLAUDE.md names only paths that exist', () => {
  const md = readFileSync(join(repoRoot, 'CLAUDE.md'), 'utf8');
  const paths = documentedPaths(md);

  it('extracted a meaningful set of paths (anti-vacuity)', () => {
    // A regex that silently matched nothing would make the assertion below
    // trivially green — which is how a guard like this rots.
    expect(paths.length).toBeGreaterThan(30);
  });

  it('every documented file path resolves', () => {
    const missing = paths.filter(p => !existsSync(join(repoRoot, p)));
    expect(missing, `CLAUDE.md names ${missing.length} path(s) that do not exist`).toEqual([]);
  });
});
