import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, BrokenTier, compileHex } from './tier-harness.js';

/**
 * N-333 — the native Go spellings docs/formats/go.md lists in its "Type Mapping"
 * table (`int64` -> bigint, `bool` -> boolean) are accepted by every tier on a
 * `.runar.go` contract, and map to the SAME Rúnar type everywhere.
 *
 * Before the fix `int64` was refused by the TS, Go and Ruby tiers and `bool` by
 * the Go tier (as a parameter or field type; Go already took it as a result
 * type), while the other tiers took both. The mapped type is checked through
 * the emitted locking script: each case USES the value (`x == a`, `Assert(x)`),
 * so a wrong mapping would be a type error or different bytes, and the hex must
 * equal the hex of the same contract spelled with `runar.Int` / `runar.Bool`.
 *
 * What this proves:
 *   - for `int64` and `bool`, in a public-method parameter, a private-method
 *     parameter and result, and a field, all seven tiers accept the native
 *     spelling and emit exactly the bytes of the `runar.Int` / `runar.Bool`
 *     spelling (and so all seven agree with each other);
 *   - `byte`, `error`, `int32` and `float64` (which no tier maps and the doc
 *     does not list) stay refused by all seven tiers as a parameter type.
 * What it does NOT prove:
 *   - the names the doc is silent on (`int`, `uint`, `uint64`, `[]byte`,
 *     `string`): tiers still disagree on those and that is escalated, not
 *     decided here;
 *   - local-variable annotations or conversions such as `int64(x)`.
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n333-'));

interface Case { id: string; native: string; ctrl: string; src: (ty: string) => string }

const HEAD = `package contract

import runar "github.com/icellan/runar/packages/runar-go"
`;

const intCases: Case[] = [
  { id: 'public param', native: 'int64', ctrl: 'runar.Int', src: (ty) => `${HEAD}
type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Arithmetic) Verify(a runar.Int, x ${ty}) {
	runar.Assert(x == a)
	runar.Assert(a == c.Target)
}
` },
  { id: 'private param and result', native: 'int64', ctrl: 'runar.Int', src: (ty) => `${HEAD}
type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Arithmetic) helper(x ${ty}) ${ty} {
	return x + 1
}

func (c *Arithmetic) Verify(a runar.Int) {
	runar.Assert(c.helper(a) == c.Target)
}
` },
  { id: 'field', native: 'int64', ctrl: 'runar.Int', src: (ty) => `${HEAD}
type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
	Extra  ${ty} \`runar:"readonly"\`
}

func (c *Arithmetic) Verify(a runar.Int) {
	runar.Assert(a == c.Target + c.Extra)
}
` },
];

const boolCases: Case[] = [
  { id: 'public param', native: 'bool', ctrl: 'runar.Bool', src: (ty) => `${HEAD}
type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Arithmetic) Verify(a runar.Int, x ${ty}) {
	runar.Assert(x)
	runar.Assert(a == c.Target)
}
` },
  { id: 'private param and result', native: 'bool', ctrl: 'runar.Bool', src: (ty) => `${HEAD}
type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
}

func (c *Arithmetic) helper(x ${ty}) ${ty} {
	return x
}

func (c *Arithmetic) Verify(a runar.Int, f runar.Bool) {
	runar.Assert(c.helper(f))
	runar.Assert(a == c.Target)
}
` },
  { id: 'field', native: 'bool', ctrl: 'runar.Bool', src: (ty) => `${HEAD}
type Arithmetic struct {
	runar.SmartContract
	Target runar.Int \`runar:"readonly"\`
	Flag   ${ty} \`runar:"readonly"\`
}

func (c *Arithmetic) Verify(a runar.Int) {
	runar.Assert(c.Flag)
	runar.Assert(a == c.Target)
}
` },
];

function write(src: string, tag: string): string {
  const dir = mkdtempSync(join(TMP, `${tag}-`));
  const path = join(dir, 'Arithmetic.runar.go');
  writeFileSync(path, src);
  return path;
}

function hexOrWhy(tier: (typeof TIERS)[number], path: string): string {
  try {
    return compileHex(tier, path);
  } catch (e) {
    if (!(e instanceof BrokenTier)) throw e;
    return `FAILED: ${e.message.slice(0, 200)}`;
  }
}

describe('N-333: native Go int64 / bool are accepted and mapped identically by every tier', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const c of [...intCases, ...boolCases]) {
    it(`.runar.go ${c.native} as ${c.id}: every tier emits the bytes of the ${c.ctrl} spelling`, () => {
      const nativePath = write(c.src(c.native), 'native');
      const ctrlPath = write(c.src(c.ctrl), 'ctrl');
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const ctrl = hexOrWhy(tier, ctrlPath);
        const native = hexOrWhy(tier, nativePath);
        got[tier.id] = native === ctrl && !ctrl.startsWith('FAILED') ? 'same bytes as control' : `native=${native.slice(0, 200)} control=${ctrl.slice(0, 60)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'same bytes as control'])));
    }, 900_000);
  }

  for (const name of ['byte', 'error', 'int32', 'float64']) {
    it(`.runar.go ${name} as a parameter type: refused by every tier`, () => {
      const path = write(intCases[0].src(name).replace(`x == a`, `a == a`), `refuse-${name}`);
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, path);
        got[tier.id] = r.verdict;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'rejected'])));
    }, 900_000);
  }
});
