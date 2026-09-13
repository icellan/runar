/**
 * R-255 (CL-DOC-016): the wire-protocol primitives are undocumented in the SDK
 * READMEs that implement them.
 *
 * CLAUDE.md names three things whose bytes cross a tier boundary and must
 * therefore be byte-identical in all seven SDKs: `canonicalJson`,
 * `SignedEnvelope`, and the `signEnvelope` / `verifyEnvelope` pair. The finding
 * observed that `packages/runar-go/README.md` (1835 lines) and
 * `packages/runar-rs/README.md` (2117 lines) mention none of them — full-text
 * grep, zero hits.
 *
 * Measured across all seven rather than the two the reviewer sampled: every SDK
 * implements both primitives, and NO SDK README mentioned either. The three
 * ScriptVM hits in the zig / ruby / java READMEs are the notes saying they do
 * NOT have one.
 *
 * It matters more here than "some API is undocumented" usually does. These are
 * the functions whose output another tier's verifier consumes: a reader who
 * does not know `canonicalJson` exists writes `json.Marshal` instead, the bytes
 * differ by key order, and every signature that crosses a tier boundary fails —
 * at runtime, in someone else's process.
 *
 * The test derives the requirement from the source: an SDK that EXPORTS these
 * has to name them in its README. An SDK that drops the primitive stops being
 * required to document it, and a new SDK inherits the requirement.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** SDK package dir -> the source tree that would carry the primitives. */
const SDKS: Record<string, string> = {
  'runar-sdk': 'src',
  'runar-go': '.',
  'runar-rs': 'src',
  'runar-py': 'runar',
  'runar-zig': 'src',
  'runar-rb': 'lib',
  'runar-java': 'src/main',
};

/** Every spelling of a primitive across the seven languages. */
const ENVELOPE = /SignedEnvelope|signEnvelope|sign_envelope/;
const CANONICAL = /canonicalJson|canonical_json|CanonicalJSON/;

function sourceFiles(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'target' || name === 'build' || name === '.git') continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) sourceFiles(p, out);
    else if (/\.(ts|go|rs|py|zig|rb|java)$/.test(name) && !/test|spec/i.test(name)) out.push(p);
  }
  return out;
}

function implementsPrimitive(pkg: string, re: RegExp): boolean {
  const root = join(ROOT, 'packages', pkg, SDKS[pkg]!);
  return sourceFiles(root).some((f) => re.test(readFileSync(f, 'utf8')));
}

const readme = (pkg: string) => readFileSync(join(ROOT, 'packages', pkg, 'README.md'), 'utf8');

describe('R-255: an SDK that ships a wire primitive documents it', () => {
  it('the scan finds all seven SDKs', () => {
    for (const pkg of Object.keys(SDKS)) {
      expect(existsSync(join(ROOT, 'packages', pkg, 'README.md')), `${pkg} has no README`).toBe(true);
    }
    expect(Object.keys(SDKS).length).toBe(7);
  });

  for (const pkg of Object.keys(SDKS)) {
    it(`${pkg} documents the signed envelope`, () => {
      if (!implementsPrimitive(pkg, ENVELOPE)) return; // not shipped here
      expect(
        ENVELOPE.test(readme(pkg)),
        `${pkg} implements the signed envelope and its README never names it — ` +
          `the reader cannot discover the one API whose bytes another tier verifies`,
      ).toBe(true);
    });

    it(`${pkg} documents canonicalJson`, () => {
      if (!implementsPrimitive(pkg, CANONICAL)) return;
      expect(
        CANONICAL.test(readme(pkg)),
        `${pkg} implements canonical JSON and its README never names it — a reader ` +
          `who reaches for the language's own JSON encoder breaks every cross-tier signature`,
      ).toBe(true);
    });
  }
});
