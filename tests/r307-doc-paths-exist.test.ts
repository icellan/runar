/**
 * Every concrete repo path that `README.md`, `docs/` or `spec/` names must
 * exist — files AND directories.
 *
 * `tests/claude-md-paths-exist.test.ts` established this check for CLAUDE.md
 * and found five dangling Ruby paths on its first run. It has two limits that
 * this guard removes:
 *
 *   1. It reads one file. The round-three audit found four more dangling paths
 *      in documents it does not look at: `docs/api-reference.md` pointing at a
 *      `docs/decompiler.md` that has never existed (the decompiler's docs are
 *      `packages/decompiler/README.md`), and `docs/sp1-fri-verifier.md`
 *      naming `proof.bin` / `vk.bin` / `vk_hash.hex` in a directory that holds
 *      `proof.postcard` and `public_values.hex`.
 *   2. It skips any path whose last segment has no file extension — so
 *      DIRECTORY paths are unchecked by design, which is how
 *      `packages/runar-zig/src/sdk/` (the SDK is 45 flat `src/sdk_*.zig`
 *      files) survived a guard written to catch exactly this. A path checker
 *      that cannot check directories has a hole shaped like the thing it
 *      missed.
 *
 * A directory reference is recognised by a trailing slash, which is how these
 * documents already write them. A path with no extension and no trailing slash
 * is ambiguous — `runar decompile` is not a file — and is skipped, same as
 * before.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Top-level directories a repo-relative path can start with. */
const ROOTS = [
  'packages/', 'compilers/', 'conformance/', 'examples/',
  'docs/', 'spec/', 'integration/', 'tests/', 'scripts/', 'tools/', '.github/',
];

/** Extracted reference: a backtick span that names something in the tree. */
interface Ref {
  path: string;
  kind: 'file' | 'dir';
}

/** Build outputs: absent from a clean checkout by design, not dangling. */
const GENERATED = /(^|\/)(build|target|dist|node_modules|zig-out|zig-pkg|coverage)(\/|$)/;

function documentedPaths(markdown: string): Ref[] {
  const found = new Map<string, Ref>();
  for (const m of markdown.matchAll(/`([^`\n]+)`/g)) {
    const raw = m[1]!.trim();
    if (!ROOTS.some((r) => raw.startsWith(r))) continue;
    // A shape, not a path: templates, globs, placeholders, elisions.
    if (/[{}<>*\s]/.test(raw)) continue;
    if (raw.includes('/.../')) continue;
    if (GENERATED.test(raw)) continue;

    if (raw.endsWith('/')) {
      found.set(raw, { path: raw.replace(/\/+$/, ''), kind: 'dir' });
      continue;
    }
    // Otherwise it must look like a file: a lowercase extension on the last
    // segment. Lowercase matters — `packages/runar-go/sp1fri.EncodeUnlockingScript`
    // is a package plus an exported symbol, not a file named `.EncodeUnlockingScript`.
    const last = raw.split('/').pop()!;
    if (!/\.[a-z0-9]{1,8}$/.test(last)) continue;
    found.set(raw, { path: raw, kind: 'file' });
  }
  return [...found.values()].sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Paths git ignores. A documented path under a gitignored tree (regtest
 * working directories, fetch caches) is legitimately absent from a clean
 * checkout, so it is not a dangling reference.
 */
function gitIgnored(paths: string[]): Set<string> {
  if (paths.length === 0) return new Set();
  try {
    // `check-ignore` exits 1 when nothing matches, which execFileSync throws on.
    const out = execFileSync('git', ['check-ignore', '--stdin'], {
      cwd: repoRoot,
      input: paths.join('\n'),
      encoding: 'utf8',
    });
    return new Set(out.split('\n').map((l) => l.trim()).filter(Boolean));
  } catch (e) {
    const out = (e as { stdout?: string }).stdout ?? '';
    return new Set(out.split('\n').map((l) => l.trim()).filter(Boolean));
  }
}

/** Markdown documents this guard covers. */
function documents(): string[] {
  const out = ['README.md'];
  for (const dir of ['docs', 'spec']) {
    const walk = (d: string, prefix: string) => {
      for (const e of readdirSync(join(repoRoot, d))) {
        const p = join(repoRoot, d, e);
        if (statSync(p).isDirectory()) continue; // one level is enough today
        if (e.endsWith('.md')) out.push(`${prefix}${e}`);
      }
    };
    walk(dir, `${dir}/`);
    // docs/formats/ carries the per-format guides.
    const sub = join(repoRoot, dir, 'formats');
    if (existsSync(sub)) {
      for (const e of readdirSync(sub)) {
        if (e.endsWith('.md')) out.push(`${dir}/formats/${e}`);
      }
    }
  }
  return out;
}

describe('R-307: documents name only paths that exist', () => {
  const docs = documents();

  it('anti-vacuity: a meaningful number of documents and paths were extracted', () => {
    // A walker that found nothing, or a regex that matched nothing, would make
    // every assertion below trivially green — which is how a guard like this
    // rots without anyone noticing.
    expect(docs.length, 'no documents collected').toBeGreaterThan(15);
    const total = docs.reduce(
      (n, d) => n + documentedPaths(readFileSync(join(repoRoot, d), 'utf8')).length,
      0,
    );
    expect(total, 'no repo paths extracted from any document').toBeGreaterThan(100);
  });

  it('anti-vacuity: directory references are actually being collected', () => {
    // The specific hole this guard exists to close: if the trailing-slash
    // branch ever stops matching, files would still pass and directories
    // would go unchecked in silence.
    const dirRefs = docs.flatMap((d) =>
      documentedPaths(readFileSync(join(repoRoot, d), 'utf8')).filter((r) => r.kind === 'dir'),
    );
    expect(dirRefs.length, 'no directory references extracted').toBeGreaterThan(10);
  });

  for (const doc of documents()) {
    it(doc, () => {
      const refs = documentedPaths(readFileSync(join(repoRoot, doc), 'utf8'));
      const ignored = gitIgnored(refs.map((r) => r.path));
      const broken = refs
        .filter((r) => !ignored.has(r.path))
        .filter((r) => {
          const abs = join(repoRoot, r.path);
          if (!existsSync(abs)) return true;
          return r.kind === 'dir' ? !statSync(abs).isDirectory() : !statSync(abs).isFile();
        })
        .map((r) => (r.kind === 'dir' ? `${r.path}/ (dir)` : r.path));
      expect(
        broken,
        `${doc} names ${broken.length} path(s) that do not exist or are the wrong kind`,
      ).toEqual([]);
    });
  }
});
