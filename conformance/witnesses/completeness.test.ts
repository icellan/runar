import { it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = join(__dirname, '..', 'tests');

const NON_SPEC_JSON = new Set(['crypto-exempt.json', 'harness-inapplicable.json']);

it('every conformance fixture is either witnessed, crypto-exempt, or harness-inapplicable', () => {
  const fixtures = readdirSync(TESTS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);

  const witnessed = new Set(
    readdirSync(__dirname)
      .filter((f) => f.endsWith('.json') && !NON_SPEC_JSON.has(f))
      .map((f) => f.replace(/\.json$/, '')),
  );

  const cryptoExempt = new Set(
    (JSON.parse(readFileSync(join(__dirname, 'crypto-exempt.json'), 'utf-8')).exempt as {
      fixture: string;
    }[]).map((e) => e.fixture),
  );

  const inapplicable = new Set(
    (JSON.parse(readFileSync(join(__dirname, 'harness-inapplicable.json'), 'utf-8')).inapplicable as {
      fixture: string;
    }[]).map((e) => e.fixture),
  );

  const uncovered = fixtures.filter(
    (f) => !witnessed.has(f) && !cryptoExempt.has(f) && !inapplicable.has(f),
  );
  expect(
    uncovered,
    `fixtures with no witness and no exemption: ${uncovered.join(', ')}`,
  ).toEqual([]);

  // Guard against typos: an exemption naming a fixture that does not exist.
  const known = new Set(fixtures);
  const strayCrypto = [...cryptoExempt].filter((f) => !known.has(f));
  const strayInapplicable = [...inapplicable].filter((f) => !known.has(f));
  expect(strayCrypto, `crypto-exempt lists unknown fixtures: ${strayCrypto.join(', ')}`).toEqual([]);
  expect(
    strayInapplicable,
    `harness-inapplicable lists unknown fixtures: ${strayInapplicable.join(', ')}`,
  ).toEqual([]);
});
