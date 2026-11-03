import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-432: the ByteString-literal hex diagnostics (odd length, non-hex
 * characters) carry the literal's `file:line:column` in every tier on the
 * `.runar.ts` surface. Before this item only the TS reference printed it;
 * Go, Rust, Python, Zig, Ruby and Java printed the bare message because
 * their ByteString literal AST nodes had no source location.
 *
 * The position is the literal's first character (its opening quote), with
 * the 0-based column of N-078. Every expected position is computed from the
 * fixture's SOURCE TEXT (`lineText.indexOf(anchor)`), never copied from a
 * compiler's output.
 *
 * What this proves: for an odd-length and a non-hex literal, each in a method
 * body and in a property initializer (`"..." as ByteString`), every one of
 * the seven tiers prints `<file>:<line>:<col>: <TS message>` on `.runar.ts`.
 * What it does NOT prove: the other eight surfaces. The TS reference's
 * hand-written parsers (01-parse-{sol,move,go,rust,python,zig,ruby,java}.ts)
 * attach no location to a ByteString literal either, so on those surfaces
 * every tier prints the message bare, which is parity with TS today.
 */

const TIERS = buildSourceTiers();
const DIR = mkdtempSync(join(tmpdir(), 'n432-literal-loc-'));

const tsMessage = (lit: string): string =>
  lit.length % 2 !== 0
    ? `ByteString literal '${lit}' has odd length (${lit.length}) — hex strings must have an even number of characters`
    : `ByteString literal '${lit}' contains non-hex characters — only 0-9, a-f, A-F are allowed`;

const propSource = (name: string, lit: string): string => `import { SmartContract, assert, ByteString } from 'runar-lang';
export class ${name} extends SmartContract {
  readonly k: ByteString = "${lit}" as ByteString;
  constructor() { super(); }
  public unlock() { assert(this.k === this.k); }
}
`;

const methodSource = (name: string, lit: string): string => `import { SmartContract, assert, ByteString, PubKey, Sig, checkSig } from 'runar-lang';

export class ${name} extends SmartContract {
  readonly pk: PubKey;

  constructor(pk: PubKey) {
    super(pk);
    this.pk = pk;
  }

  public unlock(sig: Sig, b: ByteString) {
    assert(b !== "${lit}");
    assert(checkSig(sig, this.pk));
  }
}
`;

const CASES: Array<{ name: string; lit: string; src: (n: string, l: string) => string }> = [
  { name: 'PropOdd', lit: 'abc', src: propSource },
  { name: 'PropNonHex', lit: 'zz', src: propSource },
  { name: 'MethodOdd', lit: 'abc', src: methodSource },
  { name: 'MethodNonHex', lit: 'zz', src: methodSource },
];

/** `<line>:<0-based column>` of the literal's opening quote in `text`. */
function expectedPosition(text: string, lit: string): string {
  const anchor = `"${lit}"`;
  const lines = text.split('\n');
  const idx = lines.findIndex((l) => l.includes(anchor));
  if (idx < 0) throw new Error(`anchor ${anchor} not in source`);
  return `${idx + 1}:${lines[idx]!.indexOf(anchor)}`;
}

/** The `L:C` a tier printed in front of `message` for `fileName`, or null. */
function printedPosition(diag: string, fileName: string, message: string): string | null {
  const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = diag.match(new RegExp(`${esc(fileName)}:(\\d+):(\\d+): ${esc(message)}`));
  return m ? `${m[1]}:${m[2]}` : null;
}

describe('N-432: ByteString-literal hex diagnostics carry the literal position', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const { name, lit, src } of CASES) {
    it(`${name}.runar.ts: every tier prints :<line>:<col> of "${lit}" before the TS message`, () => {
      const fileName = `${name}.runar.ts`;
      const text = src(name, lit);
      const file = join(DIR, fileName);
      writeFileSync(file, text);
      const want = expectedPosition(text, lit);
      const message = tsMessage(lit);
      const got: Record<string, string | null> = {};
      for (const tier of TIERS) {
        const r = judge(tier, file);
        expect(r.verdict, `${tier.id} must refuse ${fileName}`).toBe('rejected');
        expect(r.diag, `${tier.id} must print the TS message`).toContain(message);
        got[tier.id] = printedPosition(r.diag, fileName, message);
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, want])));
    }, 900_000);
  }
});
