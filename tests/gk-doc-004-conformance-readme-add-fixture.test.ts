/**
 * GK-DOC-004: conformance/README.md "How to Add New Test Cases" told the
 * reader to create conformance/tests/my-new-test/my-new-test.runar.ts. The
 * runner rejects that fixture: discoverFormats only reads sources declared in
 * source.json, an in-directory *.runar.* file is an "Orphan source file" hard
 * error, and every one of the nine extensions must be declared (or listed in
 * parserSkip with a parserSkipReason).
 *
 * Proves: the guide no longer puts sources in the case directory, and names
 * source.json `sources`, all nine formats, parserSkip/parserSkipReason, the
 * fold-OFF golden step, the provenance gate and the CI runner command.
 * Does not prove: that following the guide yields a green fixture.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README = readFileSync(join(ROOT, 'conformance', 'README.md'), 'utf8');
const RUNNER = readFileSync(join(ROOT, 'conformance', 'runner', 'runner.ts'), 'utf8');

function section(): string {
  const start = README.indexOf('## How to Add New Test Cases');
  const end = README.indexOf('\n## ', start + 1);
  return README.slice(start, end);
}

describe('GK-DOC-004: the add-a-fixture guide produces a fixture the runner accepts', () => {
  it('the runner still rejects in-directory sources', () => {
    expect(RUNNER).toContain('Orphan source file');
  });

  it('does not tell the reader to put a source file in the case directory', () => {
    expect(section()).not.toContain('conformance/tests/my-new-test/my-new-test.runar.ts');
    expect(section()).not.toMatch(/conformance\/tests\/[\w-]+\/[\w-]+\.runar\./);
  });

  it('describes the real fixture contract', () => {
    const s = section();
    expect(s).toMatch(/examples\//);
    expect(s).toMatch(/"sources"/);
    expect(s).toMatch(/\.runar\.java/);
    expect(s).toMatch(/parserSkipReason/);
    expect(s).toMatch(/update-golden/);
    expect(s).toMatch(/fold-OFF/);
    expect(s).toMatch(/check-golden-provenance\.mjs/);
    expect(s).toMatch(/script-size-baseline\.json/);
    expect(s).toMatch(/--multi-format/);
  });
});
