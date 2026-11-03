import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-338 — the native Go type names docs/formats/go.md does NOT list in its
 * "Type Mapping" table (`int`, `uint`, `uint64`, `[]byte`, `string`, and the
 * other native spellings no tier maps) are refused by every tier on a
 * `.runar.go` contract, in a public-method parameter, a private-method
 * parameter, a private-method result and a field. The doc is the spec: only
 * `int64`, `bool` and the `runar.*` types are accepted (N-333).
 *
 * Before the fix `int` was taken by the TS, Rust, Python, Zig, Ruby and Java
 * tiers (Go refused it); `uint`, `uint64` and `string` by Rust; `[]byte` by
 * Rust and Zig. Each contract is otherwise valid, so the only defect is the
 * type name: the control spelling `int64` in the same slot is accepted by all
 * seven tiers.
 *
 * What this proves:
 *   - for each unlisted name and each of the four slots, all seven tiers
 *     refuse, and the diagnostic names the offending type;
 *   - the same contract spelled with `int64` in that slot is accepted by all
 *     seven tiers, so the refusal is the type name and not the contract shape.
 * What it does NOT prove:
 *   - local-variable annotations or conversions such as `int(x)`;
 *   - the diagnostic wording beyond quoting the type;
 *   - names outside this list (the doc-listed names are N-333's job).
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n338-'));

const NAMES = [
  'int', 'uint', 'uint64', '[]byte', 'string',
  'int8', 'int16', 'uint8', 'uint16', 'uint32', 'uintptr', 'float32', 'rune', 'any',
];

const HEAD = `package contract

import runar "github.com/icellan/runar/packages/runar-go"
`;

type Slot = 'public param' | 'private param' | 'private result' | 'field';
const SLOTS: Slot[] = ['public param', 'private param', 'private result', 'field'];

function src(slot: Slot, ty: string): string {
  const field = slot === 'field' ? ty : 'runar.Int';
  const priv = slot === 'private param' ? ty : 'runar.Int';
  const ret = slot === 'private result' ? ty : 'runar.Int';
  const pub = slot === 'public param' ? ty : 'runar.Int';
  // A private result needs a value of its own type to return: take it as a
  // parameter of that type, so the result slot is the only unusual position
  // besides the parameter that carries the same name.
  const helperParam = slot === 'private result' ? ty : priv;
  return `${HEAD}
type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
	Extra  ${field} \`runar:"readonly"\`
}

func (c *Arithmetic) helper(x ${helperParam}) ${ret} {
	return x
}

func (c *Arithmetic) Verify(a runar.Int, d ${pub}) {
	runar.Assert(a == c.Target)
}
`;
}

let n = 0;
function write(text: string): string {
  const dir = mkdtempSync(join(TMP, `c${n++}-`));
  const path = join(dir, 'Arithmetic.runar.go');
  writeFileSync(path, text);
  return path;
}

describe('N-338: native Go type names the doc does not list are refused by every tier', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const slot of SLOTS) {
    it(`.runar.go control: int64 as ${slot} is accepted by every tier`, () => {
      const path = write(src(slot, 'int64'));
      const got: Record<string, string> = {};
      for (const tier of TIERS) got[tier.id] = judge(tier, path).verdict;
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
    }, 900_000);

    for (const name of NAMES) {
      it(`.runar.go ${name} as ${slot}: refused by every tier, naming the type`, () => {
        const path = write(src(slot, name));
        const got: Record<string, string> = {};
        const bare = name.replace('[]', '');
        for (const tier of TIERS) {
          const r = judge(tier, path);
          got[tier.id] = r.verdict === 'rejected' && r.diag.includes(bare)
            ? 'rejected'
            : `${r.verdict}: ${r.diag.slice(0, 160)}`;
        }
        expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'rejected'])));
      }, 900_000);
    }
  }
});
