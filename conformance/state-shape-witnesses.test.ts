/**
 * F-352 / CL-GAP-148: every mutable-state shape must have at least two
 * full-parity witnesses.
 *
 * The state-serialisation layout (how the mutable properties are encoded after
 * OP_RETURN and re-parsed by the continuation) depends on the ordered TYPES of
 * the mutable properties. A shape pinned by exactly one fixture is pinned by one
 * sample: a divergence that only a second contract of that shape would expose
 * (property order, a different method set, a different constructor) goes
 * unseen. Four shapes (auction, state-ripemd160, token-ft, token-nft) plus two
 * more (annotated-vault, fixed-array-write) had exactly one witness each.
 *
 * The shape of each fixture is DERIVED FROM THE COMPILER, not regexed from the
 * source: the fixture's .runar.ts is compiled with the TypeScript compiler and
 * the artifact's `stateFields` (the mutable, non-readonly properties) are read.
 * Only fixtures with NO `compilers` allowlist count as witnesses, because only
 * those require byte-identical hex + ANF from all seven tiers.
 *
 * Proves: no mutable-property type multiset that appears in the corpus is
 * pinned by fewer than two seven-tier fixtures. Does not prove: that the two
 * witnesses differ in anything but their method bodies, nor that shapes absent
 * from the corpus entirely (CL-GAP-147) are covered; nor does a count of two
 * say the witnesses exercise the state codec differently.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

const HERE = resolve(dirname(fileURLToPath(import.meta.url)));
const TESTS = join(HERE, 'tests');
const MIN_WITNESSES = 2;

interface Fixture {
  name: string;
  allowlisted: boolean;
  shape: string;
}

/**
 * N-314 (R144): a fixture whose `compilers` allowlist excludes ts AND which the
 * TS compiler cannot compile (no codegen for it) is skipped here. Being
 * allowlisted it can never count as a witness anyway. The skip is BY NAME: only
 * fixtures listed here AND allowlisted away from ts are skipped, and the skipped
 * set is pinned below — every other allowlisted fixture (babybear, merkle-proof,
 * state-covenant, …) is still compiled, and a new uncompilable one fails loudly.
 */
const EXPECTED_NOT_TS_COMPILABLE = ['bn254-pairing'];
const skippedNotTs: string[] = [];

function loadFixtures(): Fixture[] {
  const out: Fixture[] = [];
  skippedNotTs.length = 0;
  for (const name of readdirSync(TESTS).sort()) {
    const sj = join(TESTS, name, 'source.json');
    if (!existsSync(sj)) continue;
    const cfg = JSON.parse(readFileSync(sj, 'utf-8')) as {
      sources: Record<string, string>;
      compilers?: string[];
    };
    if (Array.isArray(cfg.compilers) && !cfg.compilers.includes('ts')
      && EXPECTED_NOT_TS_COMPILABLE.includes(name)) {
      skippedNotTs.push(name);
      continue;
    }
    const tsRel = cfg.sources['.runar.ts'];
    if (!tsRel) throw new Error(`${name}: source.json has no .runar.ts source`);
    const file = resolve(TESTS, name, tsRel);
    const result = compile(readFileSync(file, 'utf-8'), { fileName: file });
    if (!result.artifact) {
      throw new Error(`${name}: the TS compiler produced no artifact: ${JSON.stringify(result.diagnostics)}`);
    }
    const fields = result.artifact.stateFields ?? [];
    out.push({
      name,
      allowlisted: Array.isArray(cfg.compilers),
      shape: fields.map((f) => f.type).sort().join(','),
    });
  }
  return out;
}

describe('every mutable-state shape has >= 2 full-parity witnesses (F-352)', () => {
  const fixtures = loadFixtures();
  const stateful = fixtures.filter((f) => f.shape !== '');

  it('skips exactly the expected fixtures whose allowlist excludes ts (N-314)', () => {
    expect(skippedNotTs.sort()).toEqual(EXPECTED_NOT_TS_COMPILABLE);
  });

  it('sees a non-trivial stateful corpus (anti-vacuity)', () => {
    expect(stateful.length).toBeGreaterThan(20);
    expect(new Set(stateful.map((f) => f.shape)).size).toBeGreaterThan(8);
  });

  it(`pins each distinct shape with at least ${MIN_WITNESSES} non-allowlisted fixtures`, () => {
    const byShape = new Map<string, string[]>();
    for (const f of stateful) {
      if (!byShape.has(f.shape)) byShape.set(f.shape, []);
      if (!f.allowlisted) byShape.get(f.shape)!.push(f.name);
    }
    const thin = [...byShape.entries()]
      .filter(([, w]) => w.length < MIN_WITNESSES)
      .map(([shape, w]) => `{${shape}}: ${w.length} witness(es) [${w.join(', ')}]`);
    expect(thin, 'mutable-state shapes with fewer than two seven-tier witnesses').toEqual([]);
  });
});
