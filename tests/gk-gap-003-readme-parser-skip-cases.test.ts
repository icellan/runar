/**
 * GK-GAP-003 follow-up: conformance/README.md "How to Add New Test Cases"
 * said a format may leave `sources` through parserSkip "today only
 * `FixedArray` on the Java surface". The ternary-expression fixture
 * (GK-GAP-003) parserSkips the four surfaces that have no conditional
 * expression (.runar.move, .runar.go, .runar.rs, .runar.zig), so that
 * "only" became false.
 *
 * Proves: every extension that any fixture's source.json lists in
 * parserSkip is named in the guide's parserSkip sentence, and the sentence
 * no longer claims a single case.
 * Does not prove: that each skip is justified; allowlist-audit.test.ts
 * (APPROVED_PARSER_SKIPS) gates that per fixture and per format.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README = readFileSync(join(ROOT, 'conformance', 'README.md'), 'utf8');
const TESTS = join(ROOT, 'conformance', 'tests');

function guideSkipSentence(): string {
  const start = README.indexOf('## How to Add New Test Cases');
  const end = README.indexOf('\n## ', start + 1);
  const line = README.slice(start, end).split('\n').find((l) => l.includes('genuinely cannot express'));
  if (line === undefined) throw new Error('the add-a-fixture guide lost its parserSkip sentence');
  return line;
}

function skippedExtensions(): Map<string, string[]> {
  const byExt = new Map<string, string[]>();
  for (const name of readdirSync(TESTS).sort()) {
    const file = join(TESTS, name, 'source.json');
    if (!existsSync(file)) continue;
    const { parserSkip = [] } = JSON.parse(readFileSync(file, 'utf8')) as { parserSkip?: string[] };
    for (const ext of parserSkip) byExt.set(ext, [...(byExt.get(ext) ?? []), name]);
  }
  return byExt;
}

describe('GK-GAP-003: the add-a-fixture guide names every parserSkip case in the corpus', () => {
  it('the corpus skips a surface other than Java (else the check below is vacuous)', () => {
    expect([...skippedExtensions().keys()].filter((e) => e !== '.runar.java').length).toBeGreaterThan(0);
  });

  it('names every extension a fixture parserSkips', () => {
    const sentence = guideSkipSentence();
    const missing = [...skippedExtensions()]
      .filter(([ext]) => !sentence.includes(ext))
      .map(([ext, fixtures]) => `${ext} (skipped by ${fixtures.join(', ')})`);
    expect(missing).toEqual([]);
  });

  it('does not claim a single case', () => {
    expect(guideSkipSentence()).not.toMatch(/today only/);
  });
});
