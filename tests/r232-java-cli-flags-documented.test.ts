/**
 * R-232 (CL-DOC-009): compilers/java/README.md and the CLI `--help` omitted
 * real flags.
 *
 * Measured when this was written: the Cli accepts 12 flags and `--help` listed
 * 11 — `--parse-only` was accepted, worked (it prints "parser ok"), and was
 * mentioned by no output at all. The README's "CLI Contract" table listed 4 and
 * omitted `--parse-only`, `--emit-ir-to`, `--emit-source-map`,
 * `--emit-artifact` and `--daemon` entirely.
 *
 * `--parse-only` is not a minor omission: it is what the conformance runner's
 * all-tier parser-only matrix invokes.
 *
 * This test derives the flag set from the SOURCE — the string literals the
 * argument parser compares against — so a flag added tomorrow has to be
 * documented in both places or this fails.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(ROOT, 'compilers/java/src/main/java/runar/compiler/Cli.java');
const README = join(ROOT, 'compilers/java/README.md');

/** Long flags the Cli's argument parser compares against. */
function acceptedFlags(): string[] {
  const src = readFileSync(CLI, 'utf8');
  const found = new Set<string>();
  for (const m of src.matchAll(/"(--[a-z][a-z-]*)"/g)) found.add(m[1]!);
  return [...found].sort();
}

describe('R-232: every Java CLI flag is documented', () => {
  it('found a plausible flag set', () => {
    const flags = acceptedFlags();
    expect(flags.length, 'the flag scan broke').toBeGreaterThan(8);
    expect(flags).toContain('--parse-only');
    expect(flags).toContain('--source');
  });

  it('appears in --help', () => {
    const src = readFileSync(CLI, 'utf8');
    // Scope to the usage block itself. Slicing to end-of-file would also pick
    // up the argument parser's own string literals, and then every accepted
    // flag would "appear" in the help by construction — which is exactly how a
    // first draft of this test passed with --parse-only removed from the
    // banner.
    const helpStart = src.indexOf('Usage: runar-java');
    expect(helpStart, 'the usage banner has moved').toBeGreaterThan(0);
    const helpEnd = src.indexOf('print this help and exit', helpStart);
    expect(helpEnd, 'the end of the usage block has moved').toBeGreaterThan(helpStart);
    const help = src.slice(helpStart, helpEnd);

    const undocumented = acceptedFlags().filter((f) => !help.includes(f));
    expect(
      undocumented,
      'these flags are accepted but not listed by --help',
    ).toEqual([]);
  });

  it('appears in the README CLI table', () => {
    const readme = readFileSync(README, 'utf8');
    const undocumented = acceptedFlags().filter((f) => !readme.includes(f));
    expect(
      undocumented,
      'these flags are accepted but absent from compilers/java/README.md',
    ).toEqual([]);
  });
});
