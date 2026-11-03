import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { REPO, Tier, buildSourceTiers, compileHex, ALL_TIER_IDS } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-216 (+ N-231, grouped by user decision R141) — branch-reconcile rolls
 * carried `roll.depth = d + 1` while pushing `d`.
 *
 * `lowerIf`'s post-ENDIF reconcile and `lowerUpdateProp` emit
 * `push(d) + roll{depth} + drop`. The emitter never reads `roll.depth` (the
 * runtime operand is the pushed `d`), but every typed peephole does: the rules
 * `PUSH 0 + Roll{0} -> []`, `PUSH 1 + Roll{1} -> SWAP` and
 * `PUSH 2 + Roll{2} -> ROT` match on the PAIR, and at these sites the pair
 * disagreed (push d, roll{d + 1}), so the fold could never fire and the
 * script kept a two-byte `OP_d OP_ROLL` where one byte (or none) does the same
 * thing. Six sites per tier carried it:
 *   1. the declared-results stale-slot drop loop (`sinkBelow` accumulation),
 *   2. the `sinkBelow` restore loop (push windowSize - 1, roll{windowSize}) —
 *      this is N-231: assert-false-guard's residual `OP_2 OP_ROLL`s,
 *   3. the N >= 2 conditional-write reconcile,
 *   4. the both-arms-wrote-the-same-property reconcile,
 *   5. the if-without-else stale-local reconcile,
 *   6. `lowerUpdateProp`'s stale-entry drop.
 * Zig has no typed depth (it hand-folds per site) and the Lean model
 * hand-emitted `push d, OP_ROLL`; both now emit the folded bytes directly.
 *
 * What this proves:
 *   - for every available tier, fold OFF and ON, the moved fixtures that
 *     exercise sites 1, 2, 3, 5 and 6 (if-else, assert-false-guard,
 *     branch-merged-locals, cond-write-multi-field, loop-if-merged-locals,
 *     token-ft, auction, state-covenant-mechanics) compile to a script in
 *     which NO `OP_0|OP_1|OP_2 OP_ROLL` opcode pair remains — checked by
 *     walking the script opcode by opcode, so push data can neither fake nor
 *     hide a match — and every tier emits the TS bytes, fold OFF equal to the
 *     checked-in golden;
 *   - the checked-in golden of EVERY fixture that moved carries no such pair;
 *   - for if-else, branch-merged-locals and assert-false-guard, the new golden
 *     is the pre-fix golden with exactly its `<k> OP_ROLL` pairs (k = 0/1/2)
 *     replaced by the folded form (k = 0: removed, 1: OP_SWAP, 2: OP_ROT) and
 *     nothing else changed; for assert-false-guard that is all six pre-fix
 *     `OP_2 OP_ROLL` pairs plus two `OP_1 OP_ROLL` (N-231).
 * What it does NOT prove: behaviour. Semantic equivalence of the rewrite is
 * the per-fixture execution evidence in conformance/witnesses (route A
 * goldenHashes re-pinned on the new bytes, run on @bsv/sdk Spend). Site 4 is
 * not reached by any in-repo contract (liftBranchUpdateProps flattens every
 * shape tried), so its fold is covered only by the per-tier code change. Nor
 * does it say anything about other `push k / roll` mismatches outside these
 * six sites.
 */

const PRE_IF_ELSE =
  '767600877c51879b69007c637c00937677677c0094767768517a7500a0';
const PRE_BRANCH_MERGED_LOCALS =
  '61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f51' +
  '7f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c' +
  '7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136' +
  'd08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d949593777692' +
  '7f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7692' +
  '7f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c' +
  '7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c' +
  '7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802' +
  '7c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad76' +
  '01687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775' +
  '527f7768686857798252947b7c7f8201119d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f' +
  '7782012c947f758258947f758260947f77587f7c817c816e577a00a063577a7652797b7567577a5279787b7568527a75' +
  '527a7502e8035879016a7e537a58807e7b58807e827602fd009f635280517f756776030000019f635380527f7501fd7c' +
  '7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e557a557a00787c9c' +
  '9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa537a820128947f7701207f7587777777';
const PRE_ASSERT_FALSE_GUARD =
  '61ab76009c63757676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f' +
  '517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e' +
  '7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e' +
  '9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d94' +
  '95937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f' +
  '76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f' +
  '7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e' +
  '7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b' +
  '16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a' +
  '1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375' +
  '587f776775527f7768686857798252947b7c7f8201199d517f75016a880261ab7c7e8869768254947f7701007e810141' +
  '9d7601687f7782012c947f758258947f75820118947f77587f7c817c587f7c817c81577900a0635279587a9376776700' +
  '695279587a7568537a75527a527a5379820134947f77587f758155797ca269567a567a00787c9c9163041976a9147b7e' +
  '0288ac7e7c58807c7e67007b757768537a5880537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd' +
  '009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e67598058' +
  '7f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f75877767519d7676aa517f517f517f517f517f517f' +
  '517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f' +
  '517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e' +
  '7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffff' +
  'ffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76' +
  '927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76' +
  '927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e' +
  '7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be' +
  '667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7' +
  'f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e81' +
  '7602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686858798252947b7c7f820119' +
  '9d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f75820118947f' +
  '77587f7c817c587f7c817c81005979916358797653797b75675979519c63587976776700697868527a75517a52795279' +
  '68537a75537a75527a755159799163587a7653795b7a757b7567597a519c63587a767767006978597a7568527a75517a' +
  '5279527968537a75537a75527a755379820134947f77587f758155797ca269567a567a00787c9c9163041976a9147b7e' +
  '0288ac7e7c58807c7e67007b757768537a5880537a58807e7b58807e5279547a7c7558806b5379016a7e7c7e827602fd' +
  '009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e67598058' +
  '7f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f75877768';

/** Fixtures whose script moved under this fix (fold OFF and ON alike). */
const MOVED = [
  'add-raw-output', 'assert-false-guard', 'auction', 'branch-merged-locals',
  'branched-readonly-len', 'cond-write-multi-field', 'function-patterns', 'if-else',
  'loop-if-merged-locals', 'merge-locals-prop-updates', 'merge-locals-shapes',
  'property-shadow', 'state-bigint-edges', 'state-covenant', 'state-covenant-mechanics',
  'state-leaderboard', 'state-ledger', 'state-notary', 'token-ft',
];
/** The subset compiled live by every tier: together they reach sites 1, 2, 3, 5 and 6. */
const LIVE = [
  'if-else', 'assert-false-guard', 'branch-merged-locals', 'cond-write-multi-field',
  'loop-if-merged-locals', 'token-ft', 'auction', 'state-covenant-mechanics',
];

const OP_ROLL = '7a';
const FOLD: Record<string, string[]> = { '00': [], '51': ['7c'], '52': ['7b'] };

/** Split a script into whole opcodes (opcode byte plus any push payload). */
function walk(hex: string): string[] {
  const b = Buffer.from(hex, 'hex');
  const ops: string[] = [];
  let i = 0;
  while (i < b.length) {
    const op = b[i]!;
    const start = i++;
    if (op >= 0x01 && op <= 0x4b) i += op;
    else if (op === 0x4c) i += 1 + b[i]!;
    else if (op === 0x4d) i += 2 + b.readUInt16LE(i);
    else if (op === 0x4e) i += 4 + b.readUInt32LE(i);
    if (i > b.length) throw new Error(`truncated push at byte ${start}`);
    ops.push(b.subarray(start, i).toString('hex'));
  }
  return ops;
}

/** Every `OP_0|OP_1|OP_2 OP_ROLL` pair, as `"<k> 7a @<op index>"`. */
function unfoldedRolls(ops: string[]): string[] {
  const hits: string[] = [];
  for (let k = 0; k + 1 < ops.length; k++) {
    if (ops[k]! in FOLD && ops[k + 1] === OP_ROLL) hits.push(`${ops[k]} 7a @${k}`);
  }
  return hits;
}

/** The pre-fix op list with every `<k> OP_ROLL` pair folded. */
function foldAll(ops: string[]): string[] {
  const out: string[] = [];
  for (let k = 0; k < ops.length; k++) {
    if (ops[k]! in FOLD && ops[k + 1] === OP_ROLL) {
      out.push(...FOLD[ops[k]!]!);
      k++;
      continue;
    }
    out.push(ops[k]!);
  }
  return out;
}

const count = (ops: string[], k: string) => unfoldedRolls(ops).filter((h) => h.startsWith(`${k} `)).length;
const golden = (f: string) =>
  readFileSync(join(REPO, 'conformance/tests', f, 'expected-script.hex'), 'utf-8').trim();

function tsSource(fixture: string): string {
  const dir = join(REPO, 'conformance/tests', fixture);
  const cfg = JSON.parse(readFileSync(join(dir, 'source.json'), 'utf-8')) as { sources: Record<string, string> };
  const p = resolve(dir, cfg.sources['.runar.ts']!);
  if (!existsSync(p)) throw new Error(`${fixture}: no .runar.ts source at ${p}`);
  return p;
}

const foldOff = (t: Tier): Tier => ({ ...t, argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'] });
const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TS_TIER = TIERS.find((t) => t.id === 'ts');
const MODES: { label: string; tier: (t: Tier) => Tier; golden: boolean }[] = [
  { label: 'fold OFF', tier: foldOff, golden: true },
  { label: 'fold ON', tier: (t) => t, golden: false },
];

describe('N-216 / N-231: branch-reconcile rolls fold in every tier', () => {
  it('the TS reference and at least one other tier are available (all seven in CI)', () => {
    expect(TS_TIER).toBeDefined();
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.map((t) => t.id).sort()).toEqual([...ALL_TIER_IDS]);
  });

  describe('checked-in goldens', () => {
    for (const f of MOVED) {
      it(`${f}: no OP_0/1/2 OP_ROLL pair remains`, () => {
        expect(unfoldedRolls(walk(golden(f)))).toEqual([]);
      });
    }

    const PRE: [string, string, Record<string, number>][] = [
      ['if-else', PRE_IF_ELSE, { '00': 0, '51': 1, '52': 0 }],
      ['branch-merged-locals', PRE_BRANCH_MERGED_LOCALS, { '00': 0, '51': 0, '52': 2 }],
      // N-231: six OP_2 OP_ROLL (two from the stale-slot drop loop, four from
      // the sinkBelow restore loop) and two OP_1 OP_ROLL (restore loop).
      ['assert-false-guard', PRE_ASSERT_FALSE_GUARD, { '00': 0, '51': 2, '52': 6 }],
    ];
    for (const [f, pre, counts] of PRE) {
      it(`${f}: the golden is the pre-fix golden with exactly its <k> OP_ROLL pairs folded`, () => {
        const old = walk(pre);
        for (const [k, n] of Object.entries(counts)) expect(count(old, k), `pre-fix ${k} 7a count`).toBe(n);
        const now = walk(golden(f));
        expect(now).toEqual(foldAll(old));
        const pairs = Object.values(counts).reduce((a, b) => a + b, 0);
        expect(golden(f).length / 2).toBe(pre.length / 2 - pairs - counts['00']!);
      });
    }
  });

  for (const f of LIVE) {
    for (const mode of MODES) {
      describe(`${f} (${mode.label})`, () => {
        const src = tsSource(f);
        let tsHex = '';
        beforeAll(() => {
          tsHex = compileHex(mode.tier(TS_TIER!), src);
        }, 240_000);

        for (const tier of TIERS) {
          it(`${tier.id}: no OP_0/1/2 OP_ROLL pair, TS bytes${mode.golden ? ', golden' : ''}`, () => {
            const hex = tier.id === 'ts' ? tsHex : compileHex(mode.tier(tier), src);
            expect(unfoldedRolls(walk(hex))).toEqual([]);
            expect(hex).toBe(tsHex);
            if (mode.golden) expect(hex).toBe(golden(f));
          }, 240_000);
        }
      });
    }
  }
});
