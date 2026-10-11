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
});
