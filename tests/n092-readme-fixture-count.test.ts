import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

describe('N-092: README conformance fixture count consistency', () => {
  it('should have consistent fixture count between README and conformance/tests/', () => {
    // Count actual fixture directories in conformance/tests/
    const conformanceTestsDir = path.join(__dirname, '..', 'conformance', 'tests');
    const fixtures = fs.readdirSync(conformanceTestsDir)
      .filter(f => fs.statSync(path.join(conformanceTestsDir, f)).isDirectory());

    const actualCount = fixtures.length;

    // Extract claimed count from README
    const readmePath = path.join(__dirname, '..', 'runar-verification', 'README.md');
    const readmeContent = fs.readFileSync(readmePath, 'utf-8');

    // Look for the line: "| Conformance fixtures discovered (Lean-recognised) | N/N (dynamic readDir) |"
    const discoveredMatch = readmeContent.match(/Conformance fixtures discovered.*?\|\s*(\d+)\/(\d+)/);
    expect(discoveredMatch, 'Could not find "Conformance fixtures discovered" row in README').toBeTruthy();

    const readmeClaimedCount = parseInt(discoveredMatch![1], 10);

    expect(
      readmeClaimedCount,
      `README claims ${readmeClaimedCount} fixtures but conformance/tests/ contains ${actualCount} directories`
    ).toBe(actualCount);
  });

  it('should have byte-exact denominator matching the fixture count', () => {
    // Count actual fixture directories in conformance/tests/
    const conformanceTestsDir = path.join(__dirname, '..', 'conformance', 'tests');
    const fixtures = fs.readdirSync(conformanceTestsDir)
      .filter(f => fs.statSync(path.join(conformanceTestsDir, f)).isDirectory());

    const actualCount = fixtures.length;

    // Extract byte-exact row from README
    const readmePath = path.join(__dirname, '..', 'runar-verification', 'README.md');
    const readmeContent = fs.readFileSync(readmePath, 'utf-8');

    // Look for: "| Default byte-exact gate (`pipelineGolden`) | 69/88 byte-exact ..."
    const byteExactMatch = readmeContent.match(/Default byte-exact gate.*?\|\s*(\d+)\/(\d+)\s+byte-exact/);
    expect(byteExactMatch, 'Could not find byte-exact row in README').toBeTruthy();

    const denominator = parseInt(byteExactMatch![2], 10);

    expect(
      denominator,
      `Byte-exact denominator is ${denominator} but actualCount is ${actualCount}`
    ).toBe(actualCount);
  });

  // N-305: every fixture-count claim in the README body (not just the status
  // table) must track conformance/tests/. Proves: the listed claim shapes
  // equal the on-disk fixture count, and the "N baseline + M crypto-pending"
  // split sums to it. Does not prove the VERIFIED / byte-exact numerators,
  // which only a Lean run measures; those were re-measured by hand and are
  // recorded in the N-305 log.
  it('should not carry stale fixture counts outside the status table', () => {
    const conformanceTestsDir = path.join(__dirname, '..', 'conformance', 'tests');
    const actualCount = fs.readdirSync(conformanceTestsDir)
      .filter(f => fs.statSync(path.join(conformanceTestsDir, f)).isDirectory()).length;
    const readme = fs.readFileSync(
      path.join(__dirname, '..', 'runar-verification', 'README.md'), 'utf-8');

    const claims: Array<{ what: string; n: number }> = [];
    const collect = (re: RegExp, group: number) => {
      for (const m of readme.matchAll(re)) claims.push({ what: m[0], n: parseInt(m[group], 10) });
    };
    collect(/ANF JSON round-trip \|\s*(\d+)\/\d+/g, 1);
    collect(/ANF JSON round-trip \|\s*\d+\/(\d+)/g, 1);
    collect(/\d+\/(\d+) VERIFIED/g, 1);
    collect(/\b0\/(\d+) VERIFIED-direct/g, 1);
    collect(/\b(\d+)-fixture corpus/g, 1);
    collect(/\bAll (\d+) (?:discovered )?fixtures/g, 1);
    collect(/\b(\d+) fixtures \(discovered/g, 1);
    collect(/\(currently (\d+)\)/g, 1);
    collect(/0\/(\d+) \u2192 N\/(\d+)/g, 1);
    collect(/\(\d+\/(\d+)\)\.\s*$/gm, 1);
    expect(claims.length, 'no count claims found; patterns drifted').toBeGreaterThan(8);
    const stale = claims.filter(c => c.n !== actualCount);
    expect(stale, `README claims differ from ${actualCount} fixtures`).toEqual([]);

    const split = readme.match(/\((\d+) baseline \+ (\d+) Go-only \+ (\d+) crypto-pending/);
    expect(split, 'bucket split sentence not found').toBeTruthy();
    expect(parseInt(split![1], 10) + parseInt(split![2], 10) + parseInt(split![3], 10)).toBe(actualCount);
  });

  // N-314 (user decision R144, "honest n092"): the VERIFIED-modulo NUMERATOR is
  // not the fixture total. Fixtures the Lean model cannot lower at all — the
  // `goOnlyFixtures` bucket of tests/PipelineGolden.lean (today `bn254-pairing`:
  // the model has no BN254 pairing lowering) — are classified
  // DEFERRED-compile-safe-error by pipelineConformance (measured 2026-10-22:
  // 97 VERIFIED-modulo + 1 DEFERRED of 98). Proves: every README VERIFIED-modulo
  // numerator equals fixtures minus that bucket, and every DEFERRED claim counts
  // and names exactly that bucket. Does not prove the Lean classification
  // itself; only a Lean run measures it.
  it('VERIFIED-modulo numerator = fixtures minus the Lean-DEFERRED (goOnlyFixtures) bucket', () => {
    const conformanceTestsDir = path.join(__dirname, '..', 'conformance', 'tests');
    const actualCount = fs.readdirSync(conformanceTestsDir)
      .filter(f => fs.statSync(path.join(conformanceTestsDir, f)).isDirectory()).length;
    const readme = fs.readFileSync(
      path.join(__dirname, '..', 'runar-verification', 'README.md'), 'utf-8');
    const lean = fs.readFileSync(
      path.join(__dirname, '..', 'runar-verification', 'tests', 'PipelineGolden.lean'), 'utf-8');
    const bucket = lean.match(/def goOnlyFixtures : List String := \[([^\]]*)\]/);
    expect(bucket, 'goOnlyFixtures bucket not found in PipelineGolden.lean').toBeTruthy();
    const deferred = [...bucket![1].matchAll(/"([^"]+)"/g)].map(m => m[1]!).sort();
    expect(deferred, 'the Lean-DEFERRED set changed: re-measure pipelineConformance').toEqual(['bn254-pairing']);

    const numerators = [...readme.matchAll(/\*\*(\d+)\/(\d+) VERIFIED-modulo/g)]
      .concat([...readme.matchAll(/^(\d+)\/(\d+) fixtures \(discovered dynamically\) classified/gm)]);
    expect(numerators.length, 'no VERIFIED-modulo claims found; patterns drifted').toBeGreaterThan(3);
    for (const m of numerators) {
      expect(parseInt(m[1]!, 10), m[0]).toBe(actualCount - deferred.length);
      expect(parseInt(m[2]!, 10), m[0]).toBe(actualCount);
    }

    const deferredClaims = [...readme.matchAll(/\b(\d+)\/(\d+) DEFERRED[^`]*`([a-z0-9-]+)`/g)];
    expect(deferredClaims.length, 'no DEFERRED claim found').toBeGreaterThan(0);
    for (const m of deferredClaims) {
      expect(parseInt(m[1]!, 10), m[0]).toBe(deferred.length);
      expect(parseInt(m[2]!, 10), m[0]).toBe(actualCount);
      expect(deferred, m[0]).toContain(m[3]);
    }
  });
});
