/**
 * R-278 (CL-GAP-058): two dead blocks in the blackjack demo's regtest.sh.
 *
 * 1. Lines 15-20 write a hardcoded BIP32 extended private key to
 *    `$HOME/.keystore/ps.key`. Nothing in this repository reads that path — the
 *    only references to it are the three lines that create it. A demo script
 *    that plants a fixed private key in the user's home directory, for no
 *    consumer, is the kind of thing that is hard to explain later; and a key
 *    that is checked into a public repository is not a key, so if something ever
 *    DID read it, that would be worse than it being dead.
 *
 * 2. Lines 85-88 copy `$DIR/regtest_wallet.dat` into the node's data directory.
 *    That file does not exist anywhere in the repository, so the guard in front
 *    of the copy is always false and the block never runs.
 *
 * Both deleted. The test keeps them from coming back and, more usefully,
 * generalises: the script must not write outside its own directory, and must not
 * reference a repo-relative file that is not there.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REL = 'examples/end2end-example/webapp-blackjack/regtest.sh';
const DIR = join(ROOT, dirname(REL));

const script = () => readFileSync(join(ROOT, REL), 'utf8');

describe('R-278: the regtest demo has no dead blocks', () => {
  it('the script is where the test thinks it is', () => {
    expect(existsSync(join(ROOT, REL)), `${REL} moved`).toBe(true);
    expect(script()).toContain('docker run');
  });

  it('does not write a private key into the user home directory', () => {
    const text = script();
    expect(text, 'the script plants a key at $HOME/.keystore').not.toMatch(/\.keystore/);
    expect(text, 'a BIP32 extended private key is embedded in the script').not.toMatch(
      /\b[tx]prv[1-9A-HJ-NP-Za-km-z]{50,}/,
    );
  });

  it('writes only inside its own directory', () => {
    const offenders = script()
      .split('\n')
      .map((l, i) => [i + 1, l.trim()] as const)
      .filter(([, l]) => /(^|\s)(mkdir|cp|echo .*>)\s/.test(l) && /\$HOME|~\//.test(l))
      .map(([n, l]) => `${n}: ${l}`);
    expect(offenders, 'these lines write outside the demo directory').toEqual([]);
  });

  it('references no repo file that is not there', () => {
    const missing = [
      ...new Set([...script().matchAll(/\$DIR\/([A-Za-z0-9_.-]+)/g)].map((m) => m[1]!)),
    ]
      .filter((name) => name.includes('.'))
      .filter((name) => !existsSync(join(DIR, name)));
    expect(missing, 'referenced from $DIR but absent from the repo').toEqual([]);
  });
});
