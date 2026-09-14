/**
 * R-302 (GK-GAP-007): the conformance gate does not compare everything in an
 * artifact, and the README does not say which parts it leaves out.
 *
 * Two places drop fields, both deliberately:
 *
 *   runner.ts sortKeys()            strips `sourceLoc` before comparing ANF —
 *                                   source locations legitimately differ
 *                                   between parser implementations
 *   sdk-vertical/generate.ts        STRIPPED = ir, anf, asm, sourceMap,
 *                                   buildTimestamp
 *
 * and the main runner compares exactly two things per fixture: canonical ANF
 * JSON and script hex. `constructorSlots`, `codeSeparatorIndex`,
 * `codeSeparatorIndices` and the source map are in neither.
 *
 * None of that is wrong. What is wrong is a reader concluding from "all seven
 * compilers produce byte-identical output" that every field of the artifact is
 * gated — because `constructorSlots[].byteOffset` is what the SDKs splice
 * constructor arguments at, and a tier that got it wrong while emitting the same
 * script hex would pass this gate and deploy a contract whose arguments land in
 * the wrong place.
 *
 * The finding asks for one thing: the README lists what is outside the
 * guarantee. This test derives the list from the code, so the prose cannot drift
 * from the strip sites.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const README = join(ROOT, 'conformance/README.md');

const readme = () => readFileSync(README, 'utf8');

/** The `STRIPPED = [...]` list in the sdk-vertical generator. */
function sdkVerticalStripped(): string[] {
  const src = readFileSync(join(ROOT, 'conformance/sdk-vertical/generate.ts'), 'utf8');
  const m = src.match(/const STRIPPED = \[([^\]]+)\]/);
  expect(m, 'the STRIPPED list moved — update this test').toBeTruthy();
  return [...m![1]!.matchAll(/'([a-zA-Z]+)'/g)].map((x) => x[1]!);
}

/** The section this finding asks for. */
function limitsSection(): string {
  const text = readme();
  const start = text.indexOf('## What the byte-identical guarantee does NOT cover');
  expect(start, 'conformance/README.md has no section stating the gate limits').toBeGreaterThan(-1);
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n## ');
  return end === -1 ? rest : rest.slice(0, end);
}

describe('R-302: the conformance README states what the gate does not compare', () => {
  it('the strip-site scan is not vacuous', () => {
    expect(sdkVerticalStripped().length).toBeGreaterThanOrEqual(5);
  });

  it('names sourceLoc, which the ANF comparison strips', () => {
    expect(limitsSection()).toMatch(/sourceLoc/);
  });

  it('names every field the sdk-vertical generator strips', () => {
    const section = limitsSection();
    const missing = sdkVerticalStripped().filter((f) => !section.includes(f));
    expect(missing, 'stripped by sdk-vertical/generate.ts but absent from the README').toEqual([]);
  });

  it('names the artifact fields the main runner never compares', () => {
    const section = limitsSection();
    for (const field of ['constructorSlots', 'codeSeparatorIndex', 'sourceMap']) {
      expect(section, `${field} is not compared and the README does not say so`).toContain(field);
    }
  });
});
