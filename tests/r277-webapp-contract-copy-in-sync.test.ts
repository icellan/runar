/**
 * R-277 (CL-GAP-056): `webapp/PriceBet.runar.java` is a hand-duplicated copy of
 * `examples/end2end-example/java/.../PriceBet.runar.java` with nothing enforcing
 * sync.
 *
 * Confirmed, and they HAVE drifted — the two files no longer share a method
 * body. The webapp copy is written in the older primitive-operator style:
 *
 *     ByteString msg = num2bin(price, 8);
 *     assertThat(price > 0);
 *     if (price > strikePrice) {
 *
 * while the end2end copy uses the `Bigint` wrapper:
 *
 *     ByteString msg = num2bin(price.value(), java.math.BigInteger.valueOf(8));
 *     assertThat(price.gt(Bigint.of(0)));
 *     if (price.gt(this.strikePrice)) {
 *
 * The consequence today is benign, and that is a measurement rather than an
 * assumption: both compile, and they compile to BYTE-IDENTICAL scripts (142
 * hexchars, sha b2bb39dfcff7). The Java surface parser accepts both spellings
 * and lowers them the same way.
 *
 * So the guard is on the property that matters — the copy a playground user
 * loads must be the same CONTRACT as the reference — not on textual identity,
 * which would force the package line and the doc comments to match and would be
 * noise. If the two ever stop meaning the same thing, this fails; if someone
 * merely rewrites a comment, it does not.
 *
 * NOT COVERED, and stated rather than implied: the finding's other half —
 * "neither webapp ships any automated test" — is about the webapp's own Go
 * handlers and is untouched here.
 */

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, copyFileSync, existsSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findJavaBinary } from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const WEBAPP_COPY = 'examples/end2end-example/webapp/PriceBet.runar.java';
const REFERENCE = 'examples/end2end-example/java/src/main/java/runar/end2end/PriceBet.runar.java';

function splitCmd(s: string | null): { cmd: string | null; args: string[] } {
  if (s === null) return { cmd: null, args: [] };
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0] ?? null, args: parts.slice(1) };
}

/** Compile one copy with the Java tier and return its script hex. */
function hexOf(relPath: string): string {
  const { cmd, args } = splitCmd(findJavaBinary());
  const dir = mkdtempSync(join(tmpdir(), 'r277-'));
  try {
    const dest = join(dir, 'PriceBet.runar.java');
    copyFileSync(join(ROOT, relPath), dest);
    const res = spawnSync(cmd!, [...args, '--source', dest, '--hex'], {
      cwd: join(ROOT, 'compilers/java'),
      encoding: 'utf-8',
      timeout: 300_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    if (res.status !== 0) {
      throw new Error(`${relPath} did not compile: ${(res.stderr || '').slice(0, 400)}`);
    }
    const hex = (res.stdout.split('\n')[0] ?? '').replace(/\s/g, '').toLowerCase();
    if (!/^[0-9a-f]+$/.test(hex)) {
      throw new Error(`${relPath} printed no hex: ${res.stdout.slice(0, 200)}`);
    }
    return hex;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const javaAvailable = findJavaBinary() !== null;
const maybe = javaAvailable ? it : it.skip;

describe('R-277: the webapp contract copy still means what the reference means', () => {
  it('both files are present', () => {
    // If either moves, the compile cases below would fail for the wrong reason.
    expect(existsSync(join(ROOT, WEBAPP_COPY)), `${WEBAPP_COPY} is gone`).toBe(true);
    expect(existsSync(join(ROOT, REFERENCE)), `${REFERENCE} is gone`).toBe(true);
  });

  it('they really are separate files, not a symlink that makes this vacuous', () => {
    const a = readFileSync(join(ROOT, WEBAPP_COPY), 'utf-8');
    const b = readFileSync(join(ROOT, REFERENCE), 'utf-8');
    expect(a, 'the copies are byte-identical — this guard has nothing to catch').not.toBe(b);
  });

  maybe('and they compile to the same script', () => {
    const webapp = hexOf(WEBAPP_COPY);
    const reference = hexOf(REFERENCE);
    expect(webapp.length, 'the webapp copy compiled to nothing').toBeGreaterThan(20);
    expect(
      webapp,
      'the playground copy and the reference are no longer the same contract',
    ).toBe(reference);
  }, 300_000);
});
