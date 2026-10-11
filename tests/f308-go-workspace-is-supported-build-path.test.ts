/**
 * F-308 (R79 — "Workspace-only, document") — `compilers/go` (and its sibling
 * go.work members) are published Go modules, but standalone (`GOWORK=off`)
 * builds of them are NOT actually supported today: `compilers/go/go.mod` has
 * no `require` for `packages/runar-go` at all even though its source imports
 * it, and `packages/runar-go/go.mod` requires `compilers/go@v1.0.0-rc.1` --
 * a version that was never published (published `compilers/go` tags top out
 * at v0.4.5) -- while a NOTE comment in that same file claimed the require
 * "must point at a real published tag". It doesn't; the project decided
 * (R79) to document go.work as the one supported build path instead of
 * chasing `go mod tidy`/`replace`/new tags (tracked separately as N-204).
 *
 * This test pins two things:
 *   1. every go.work member still builds in WORKSPACE mode (no GOWORK
 *      override) -- the build path this project actually supports and CI
 *      actually exercises. This was already true before this change and
 *      must stay true.
 *   2. the specific misleading claim ("a real published tag") is gone from
 *      packages/runar-go/go.mod, and the replacement text says what's
 *      actually true: go.work is the supported path, and the require above
 *      does not point at a published tag yet.
 *
 * What this test does NOT prove: that `GOWORK=off go build` or `go get`
 * works for any of these modules (it doesn't, today -- that's the gap this
 * item documents rather than fixes) or that N-204 (publishing tags that
 * close the compilers/go <-> packages/runar-go cycle) is tracked anywhere
 * else; it only pins the go.mod comment's wording and the workspace build.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');

/** The `use (...)` paths from the root go.work file, in declaration order. */
function workMembers(): string[] {
  const text = readFileSync(join(REPO, 'go.work'), 'utf-8');
  const block = /use\s*\(([^)]*)\)/s.exec(text);
  expect(block, 'go.work: no use (...) block found').not.toBeNull();
  return block![1]!
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => l.replace(/^\.\//, ''));
}

describe('F-308/R79: go.work is the documented, working build path', () => {
  for (const member of workMembers()) {
    // conformance's root package is test-only (`go build .` fails with "no
    // non-test Go files" even on a healthy checkout) and `go build ./...`
    // there additionally descends into conformance/negatives, a directory of
    // deliberately-invalid `.runar.go` fixtures that fail as literal Go
    // source -- a pre-existing, unrelated condition. CI itself only ever
    // builds conformance via `go test -v -timeout 1200s .` (ci.yml), scoped
    // to the root package, never `./...`. `go vet .` is the fast, faithful
    // proxy for "the root package still compiles" without running the suite
    // or touching negatives/.
    const isConformance = member === 'conformance';
    const args = isConformance ? ['vet', '.'] : ['build', './...'];
    it(`${member} builds in workspace mode (go ${args.join(' ')}, no GOWORK override)`, () => {
      const cwd = join(REPO, member);
      const result = spawnSync('go', args, { cwd, encoding: 'utf8' });
      expect(result.status, `go ${args.join(' ')} in ${member} failed:\n${result.stderr}`).toBe(0);
    });
  }

  it('packages/runar-go/go.mod no longer claims compilers/go v1.0.0-rc.1 is a real published tag', () => {
    const modText = readFileSync(join(REPO, 'packages', 'runar-go', 'go.mod'), 'utf-8');
    expect(modText, 'the disproven "real published tag" claim is still present').not.toMatch(
      /real published tag/,
    );
    expect(modText, 'go.mod should say go.work is the supported build path').toMatch(
      /go\.work is the supported build path/,
    );
    expect(modText, 'go.mod should reference the N-204 tracking item').toMatch(/N-204/);
  });
});
