/**
 * R-184 (CL-BUG-084): webapp-blackjack/Dockerfile pinned `golang:1.24-bookworm`
 * while the go.mod files it builds declare `go 1.26` and the directory's own
 * README says "Go 1.26+".
 *
 * A Go toolchain older than the module's `go` directive refuses to build it, so
 * the image could not have produced a binary. Nothing caught it because no CI
 * job references this Dockerfile — it is documentation that happens to be
 * executable, and it was wrong.
 *
 * This test compares every `FROM golang:<version>` in the tree against the
 * `go` directive of the nearest go.mod, so the next drift fails here instead of
 * in someone's terminal.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git' || entry === 'target'
        || entry === '.worktrees' || entry === 'zig-cache' || entry === '.zig-cache') continue;
    const p = join(dir, entry);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walk(p, out);
    else if (entry === 'Dockerfile') out.push(p);
  }
  return out;
}

/** The `go` directive of the nearest go.mod at or above `dir`. */
function nearestGoDirective(dir: string): { version: string; path: string } | null {
  let cur = dir;
  while (cur.startsWith(ROOT)) {
    const mod = join(cur, 'go.mod');
    if (existsSync(mod)) {
      const m = readFileSync(mod, 'utf8').match(/^go\s+(\d+\.\d+)/m);
      if (m) return { version: m[1]!, path: mod };
    }
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return null;
}

describe('R-184: a golang base image must not be older than the module it builds', () => {
  it('holds for every Dockerfile in the tree', () => {
    const problems: string[] = [];
    const checked: string[] = [];

    for (const file of walk(ROOT)) {
      const text = readFileSync(file, 'utf8');
      const m = text.match(/^FROM\s+golang:(\d+)\.(\d+)/m);
      if (!m) continue;

      const declared = nearestGoDirective(dirname(file));
      if (!declared) continue;
      checked.push(file.slice(ROOT.length + 1));

      const image = [Number(m[1]), Number(m[2])] as const;
      const [wantMajor, wantMinor] = declared.version.split('.').map(Number) as [number, number];
      if (image[0] < wantMajor || (image[0] === wantMajor && image[1] < wantMinor)) {
        problems.push(
          `${file.slice(ROOT.length + 1)}: FROM golang:${image[0]}.${image[1]} ` +
            `is older than ${declared.path.slice(ROOT.length + 1)}'s "go ${declared.version}"`,
        );
      }
    }

    expect(checked.length, 'no Dockerfile with a golang base image was found — the scan broke')
      .toBeGreaterThan(0);
    expect(problems).toEqual([]);
  });
});
