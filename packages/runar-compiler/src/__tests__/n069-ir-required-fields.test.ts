import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadANFFromJSON } from '../index.js';

/**
 * N-069 — `loadANFFromJSON` checks every required ANF field for presence and
 * JSON type, and names the field's path in one diagnostic shared with the six
 * other tiers.
 *
 * Before: a method with no `name` loaded and compiled (exit 0, `00ac`); an
 * omitted `body` died as `bindings is not iterable`; `body: "not-an-array"`
 * died as `Cannot read properties of undefined (reading 'kind')`.
 *
 * Proves: each single-field corruption in the shared corpus is refused with
 * its exact diagnostic, and the control loads. Does not prove: that the six
 * native tiers agree (conformance/negatives/ir-required-fields.test.ts does),
 * or full schema conformance — deliberately defaulted optional fields are not
 * required.
 */

const CORPUS = JSON.parse(
  readFileSync(
    join(__dirname, '../../../../conformance/negatives/ir-required-fields-cases.json'),
    'utf8',
  ),
) as { control: unknown; cases: Array<{ name: string; ir: unknown; error: string }> };

describe('N-069: loadANFFromJSON required fields', () => {
  it('loads the control', () => {
    expect(() => loadANFFromJSON(JSON.stringify(CORPUS.control))).not.toThrow();
  });

  for (const c of CORPUS.cases) {
    it(`refuses ${c.name}`, () => {
      expect(() => loadANFFromJSON(JSON.stringify(c.ir))).toThrow(c.error);
    });
  }
});
