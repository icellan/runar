import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compileFromANF, loadANFFromJSON } from '../index.js';

/**
 * N-215 — the reference tier's `--from-ir` path (`loadANFFromJSON` +
 * `compileFromANF`, driven by `runar-cli compile --from-ir`) lacked IR rules
 * the six native `--ir` loaders already enforce. F-342 put TS into
 * `conformance/negatives/ir-rejection-parity.test.ts` and eleven fixtures
 * went red, the worst being I15: a contract whose only public method is the
 * constructor compiled to an EMPTY locking script at exit 0 — anyone can
 * spend it.
 *
 * Each row below is the conformance fixture itself (read in place, so this
 * test and the cross-tier gate share their inputs), fed through the same two
 * calls the CLI makes, and must be refused with the diagnostic the native
 * tiers use for that rule:
 *
 *   I06 / I15  N-113 / R-081  no public method other than the constructor
 *   I05        R-079          raw_script with an empty bytes body
 *   I10        R-163 / R-165  builtin called with the wrong number of args
 *   I19/21/23  N-131          a JSON number written in float syntax
 *   I28-I31    N-133          a loop.start string that is not `<decimal>n`
 *
 * The positive side is the falsification target for an over-broad guard: the
 * goldens those fixtures were derived from, and the N-131 integer controls,
 * must still load and compile.
 *
 * What this proves: the TS loader/compileFromANF refuses each of the eleven
 * fixtures for the stated rule, and still accepts the controls.
 * What this does not prove: cross-tier byte parity of the controls, or the
 * `runar-cli` process boundary (exit status, stderr) — both are graded by
 * the conformance/negatives IR gates (ir-rejection-parity, ir-public-
 * constructor, ir-float-boundary, ir-loop-start-boundary).
 */

const REPO = join(__dirname, '../../../..');
const NEG_DIR = join(REPO, 'conformance/negatives/ir');
const CONTROL_DIR = join(NEG_DIR, 'controls');

function compileIrFile(path: string): string {
  const program = loadANFFromJSON(readFileSync(path, 'utf-8'));
  return compileFromANF(program, { disableConstantFolding: true }).scriptHex;
}

const REFUSED: ReadonlyArray<readonly [string, RegExp]> = [
  [
    'I05-raw-script-empty-body.ir.json',
    /IR validation: method unlock binding t0 raw_script has an empty bytes body but declares in_arity 0 \/ out_arity 1; a span that emits no bytes cannot have a stack effect/,
  ],
  [
    'I06-no-public-methods.ir.json',
    /IR validation: contract Anyone has no public methods — no spending entry points; an empty locking script is anyone-can-spend/,
  ],
  [
    'I10-builtin-wrong-arity.ir.json',
    /IR validation: method go binding t1 calls cat\(\) with 1 argument\(s\); it takes 2/,
  ],
  [
    'I15-public-constructor-only.ir.json',
    /IR validation: contract Anyone has no public methods — no spending entry points; an empty locking script is anyone-can-spend/,
  ],
  ['I19-load-const-float-integral.ir.json', /IR JSON contains a floating-point number \(1\.0\)/],
  ['I21-loop-count-float.ir.json', /IR JSON contains a floating-point number \(3\.5\)/],
  ['I23-raw-script-arity-float.ir.json', /IR JSON contains a floating-point number \(1\.0\)/],
  ['I28-loop-start-unsuffixed-decimal.ir.json', /a string start must be the `<decimal>n` form, got "5"/],
  ['I29-loop-start-non-numeric-string.ir.json', /a string start must be the `<decimal>n` form, got "abc"/],
  ['I30-loop-start-empty-string.ir.json', /a string start must be the `<decimal>n` form, got ""/],
  ['I31-loop-start-double-n-suffix.ir.json', /a string start must be the `<decimal>n` form, got "5nn"/],
];

const ACCEPTED: readonly string[] = [
  join(REPO, 'conformance/tests/asm-raw-script/expected-ir.json'),
  join(REPO, 'conformance/tests/bounded-loop/expected-ir.json'),
  join(REPO, 'conformance/tests/multi-method/expected-ir.json'),
  join(REPO, 'conformance/tests/fixed-array-index/expected-ir.json'),
  join(REPO, 'conformance/tests/stateful-counter/expected-ir.json'),
  join(CONTROL_DIR, 'C01-loop-count-zero.ir.json'),
  join(CONTROL_DIR, 'C02-loop-start-negative.ir.json'),
  join(CONTROL_DIR, 'C03-loop-step-down.ir.json'),
  join(CONTROL_DIR, 'C04-load-const-bigint-string.ir.json'),
  join(CONTROL_DIR, 'C05-load-const-negative.ir.json'),
  join(CONTROL_DIR, 'C06-raw-script-arity-int.ir.json'),
];

describe('N-215: TS --from-ir refuses what the six native --ir loaders refuse', () => {
  for (const [fixture, diagnostic] of REFUSED) {
    it(`refuses ${fixture}`, () => {
      expect(() => compileIrFile(join(NEG_DIR, fixture))).toThrow(diagnostic);
    });
  }

  for (const path of ACCEPTED) {
    it(`still compiles ${path.slice(REPO.length + 1)}`, () => {
      expect(compileIrFile(path)).toMatch(/^([0-9a-f]{2})+$/);
    });
  }

  it('the float scan ignores float-looking text inside strings and true/false/null', () => {
    const program = JSON.parse(readFileSync(join(REPO, 'conformance/tests/bounded-loop/expected-ir.json'), 'utf-8'));
    program._comment = ['1.5 and 1e3 inside a string are not numbers', true, false, null];
    expect(() => loadANFFromJSON(JSON.stringify(program))).not.toThrow();
  });

  it('a variadic builtin is held to its rule (merkleRootPoseidon2KB: 8*depth + 10)', () => {
    const ir = (args: number) =>
      JSON.stringify({
        contractName: 'Arity',
        properties: [],
        methods: [
          {
            name: 'unlock',
            isPublic: true,
            params: [],
            body: [
              { name: 't0', value: { kind: 'load_const', value: 0 } },
              { name: 't1', value: { kind: 'call', func: 'merkleRootPoseidon2KB', args: Array(args).fill('t0') } },
              { name: 't2', value: { kind: 'assert', value: 't1' } },
            ],
          },
        ],
      });
    expect(() => loadANFFromJSON(ir(11))).toThrow(
      /calls merkleRootPoseidon2KB\(\) with 11 argument\(s\); it takes 8\*depth \+ 10 arguments/,
    );
    expect(() => loadANFFromJSON(ir(9))).toThrow(/it takes at least 10 arguments \(8 leaf \+ index \+ depth\)/);
    expect(() => loadANFFromJSON(ir(18))).not.toThrow();
  });
});
