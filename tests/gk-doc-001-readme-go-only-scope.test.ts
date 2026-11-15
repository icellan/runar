/**
 * GK-DOC-001: README.md said the EVM/STARK proof-system primitives "are
 * Go-only by project policy". CLAUDE.md (R-130) says the opposite about where
 * code lives: the policy scopes what is CONFORMANCE-TESTED to the Go tier,
 * while TS/Rust/Python/Zig/Ruby carry real ports that conformance/go-only-parity/
 * (R-037) holds to "refuse, or match Go byte for byte", and Java refuses.
 *
 * Proves: the README bullet states the conformance scope and names the parity
 * harness, and no longer says the code itself is Go-only.
 * Does not prove: that the ports agree with Go (go-only-parity does that).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

describe('GK-DOC-001: README describes the Go-only scope the way CLAUDE.md does', () => {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
  const bullet = readme
    .split('\n')
    .find((l) => l.startsWith('- **Seven compilers**'));

  it('has the Seven compilers bullet', () => {
    expect(bullet, 'README "Seven compilers" bullet not found').toBeDefined();
  });

  it('does not claim the primitives are Go-only code', () => {
    expect(bullet).not.toMatch(/are Go-only by project policy/);
  });

  it('states the conformance scope and names the parity harness', () => {
    expect(bullet).toMatch(/R-130/);
    expect(bullet).toMatch(/conformance\/go-only-parity\//);
    expect(bullet).toMatch(/Java/);
  });
});
