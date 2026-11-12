import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * N-381 — `go test ./...` / `go vet ./...` in conformance/ failed at package
 * setup: negatives/*.runar.go are Rúnar Go-DSL fixtures, not real Go packages
 * (24 say `package contract`, one says `package contracts`, and several are
 * deliberately malformed), so the Go toolchain refused the directory. The fix
 * is a nested go.mod in negatives/, which makes the directory its own module
 * and removes it from the conformance module's `./...` without touching any
 * fixture byte.
 *
 * Proves: `go list -e ./...` from conformance/ reports no package from
 * negatives/ and no package-level error anywhere.
 * Does not prove: that every other package in the module builds or passes;
 * run `go test ./...` for that.
 */
const conformanceDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('N-381: conformance Go module excludes negatives/', () => {
  it('go list ./... succeeds and lists no negatives package', () => {
    const r = spawnSync('go', ['list', './...'], { cwd: conformanceDir, encoding: 'utf8' });
    // A cold module cache makes go print `go: downloading <module>` progress
    // to stderr even on success; that is not a package error, so drop it.
    const stderr = r.stderr
      .split('\n')
      .filter((l) => l && !l.startsWith('go: downloading '))
      .join('\n');
    expect(stderr).toBe('');
    expect(r.status).toBe(0);
    const pkgs = r.stdout.split('\n').filter(Boolean);
    expect(pkgs.length).toBeGreaterThan(0);
    expect(pkgs.filter((p) => p.includes('negatives'))).toEqual([]);
  });
});
