/**
 * GK-BUG-011 (docs half): docs/contract-patterns.md showed a Schnorr verifier
 * whose `verify(rPoint, s, e)` takes the challenge `e` from the spender. That
 * is forgeable for ANY public key: pick s and e, set R = s·G - e·P, and the
 * equation holds with no knowledge of the private key. It also had no `within`
 * bound on s, and it was the only copy of that shape users were pointed at,
 * while the contract the repository actually ships derives e on-chain
 * (Fiat-Shamir) and bounds s.
 *
 * The same shape sat in two more docs the verdict did not list:
 * docs/formats/ruby.md (`verify(r_point, s, e)`) and docs/testing-guide.md
 * (a TestContract example passing `e`). Both now follow the shipped contract.
 *
 * Proves: the snippet's `verify` takes exactly (rPoint, s), derives e from
 * hash256(R || P), bounds s with `within`, gates both points with ecOnCurve
 * (GK-BUG-011's pubKey gate included), the prose no longer has the spender
 * supply e, and the snippet compiles (TS, fold OFF) to the same script as
 * examples/ts/schnorr-zkp/SchnorrZKP.runar.ts; the Ruby doc snippet compiles to
 * that script too, no markdown under docs/ declares a Schnorr verify taking
 * e, and the testing-guide example passes only (rPoint, s).
 * Does not prove: anything the shipped contract does not (it is replayable and
 * nonce reuse leaks the key; its header says so).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DOC = readFileSync(join(ROOT, 'docs/contract-patterns.md'), 'utf8');

/** The "## Schnorr Zero-Knowledge Proof" section, up to the next "## " heading. */
function section(): string {
  const start = DOC.indexOf('## Schnorr Zero-Knowledge Proof');
  expect(start, 'the Schnorr section has moved or been renamed').toBeGreaterThanOrEqual(0);
  const next = DOC.indexOf('\n## ', start + 3);
  return DOC.slice(start, next === -1 ? undefined : next);
}

function snippet(): string {
  const m = /```typescript\n([\s\S]*?)```/.exec(section());
  expect(m, 'no ```typescript block in the Schnorr section').not.toBeNull();
  return m![1]!;
}

function tsHex(source: string, fileName: string): string {
  const r = compile(source, { fileName, disableConstantFolding: true });
  expect(r.success, `${fileName}: ${JSON.stringify(r.diagnostics.filter((d) => d.severity === 'error'))}`).toBe(true);
  return (r.scriptHex as string).toLowerCase();
}

describe('GK-BUG-011: the contract-patterns Schnorr snippet is the shipped contract', () => {
  it("verify takes (rPoint, s) only: the spender does not choose e", () => {
    const sig = /public\s+verify\s*\(([^)]*)\)/.exec(snippet());
    expect(sig, 'no `public verify(...)` in the snippet').not.toBeNull();
    const params = sig![1]!.split(',').map((p) => p.trim().split(':')[0]!.trim()).filter(Boolean);
    expect(params).toEqual(['rPoint', 's']);
  });

  it('derives e on-chain, bounds s, and gates both points', () => {
    const s = snippet();
    expect(s).toMatch(/const e = bin2num\(hash256\(cat\(rPoint, this\.pubKey\)\)\)/);
    expect(s).toMatch(/assert\(within\(\s*s,\s*1n,/);
    expect(s).toMatch(/assert\(ecOnCurve\(rPoint\)\)/);
    expect(s).toMatch(/assert\(ecOnCurve\(this\.pubKey\)\)/);
  });

  it('the prose does not have the spender supply the challenge', () => {
    const text = section();
    expect(text).not.toMatch(/provides `\(R, s, e\)`/);
    expect(text).not.toMatch(/Verifier\*\* sends a random challenge/);
  });

  it('compiles to the same script as examples/ts/schnorr-zkp/SchnorrZKP.runar.ts', () => {
    const shipped = readFileSync(join(ROOT, 'examples/ts/schnorr-zkp/SchnorrZKP.runar.ts'), 'utf8');
    expect(tsHex(snippet(), 'SchnorrZKP.runar.ts')).toBe(tsHex(shipped, 'SchnorrZKP.runar.ts'));
  }, 600_000);
});

/** Every markdown file under docs/, recursively. */
function docsMarkdown(dir = join(ROOT, 'docs')): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...docsMarkdown(p));
    else if (e.endsWith('.md')) out.push(p);
  }
  return out;
}

describe('GK-BUG-011: no other doc shows a spender-chosen e', () => {
  it('no docs/ markdown declares a Schnorr verify that takes e', () => {
    const offenders = docsMarkdown().filter((p) =>
      /verify\s*\(\s*(?:self\s*,\s*)?r_?[pP]oint\b[^)]*,\s*s\b[^)]*,\s*e\b/.test(readFileSync(p, 'utf8')),
    );
    expect(offenders.map((p) => p.slice(ROOT.length + 1))).toEqual([]);
  });

  it('docs/testing-guide.md calls verify with (rPoint, s) only', () => {
    const guide = readFileSync(join(ROOT, 'docs/testing-guide.md'), 'utf8');
    const calls = guide.match(/c\.call\('verify', \{[^}]*\}\)/g) ?? [];
    expect(calls.length, 'the Schnorr test example has moved').toBeGreaterThan(0);
    for (const c of calls) expect(c, c).not.toMatch(/\be\b(?!:)|\be: /);
  });

  it('docs/formats/ruby.md: the Ruby SchnorrZKP snippet compiles to the shipped script', () => {
    const md = readFileSync(join(ROOT, 'docs/formats/ruby.md'), 'utf8');
    const start = md.indexOf('### EC Operations (Schnorr ZKP)');
    expect(start, 'the Ruby Schnorr section has moved').toBeGreaterThanOrEqual(0);
    const block = /```ruby\n([\s\S]*?)```/.exec(md.slice(start));
    expect(block).not.toBeNull();
    const shipped = readFileSync(join(ROOT, 'examples/ts/schnorr-zkp/SchnorrZKP.runar.ts'), 'utf8');
    expect(tsHex(block![1]!, 'SchnorrZKP.runar.rb')).toBe(tsHex(shipped, 'SchnorrZKP.runar.ts'));
  }, 600_000);
});
