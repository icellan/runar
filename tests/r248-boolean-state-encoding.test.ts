/**
 * R-248 — five of the seven deployment SDKs mis-encoded a mutable `boolean`
 * state field, three different ways, and every one of them was fund-affecting.
 *
 * The compiler spells the type `boolean` — `bool` appears nowhere in any of
 * the seven frontends — and annotates the field `encoding: "bool1",
 * byteLength: 1`. The on-chain reader agrees: `05-stack-lower.ts` rebuilds the
 * continuation with `case 'boolean': propSizes.push(1)`. So the deployed state
 * tail must carry ONE raw byte, `01` or `00`.
 *
 * What the SDKs actually wrote, measured on `stateful-boolean-true`:
 *
 *     typescript  01          correct
 *     ruby        01          correct
 *     go          02 74727565 push-framed ASCII "true"  — 3 bytes too long
 *     java        02 74727565 same
 *     python      00          right width, ALWAYS false
 *     zig         00          same
 *     rust        panic       as_bytes() on SdkValue::Bool
 *
 * Go and Java deploy an 11-byte tail where the covenant rebuilds 9, so the
 * first spend can never match `hash256(outputs)`. Python and Zig deploy a
 * plausible 9-byte tail that says `false` whatever the caller passed, so any
 * later call that sets the flag builds a continuation the covenant rejects.
 * Rust fails closed, which is the only non-destructive one of the three.
 *
 * Nothing caught it because no fixture in the corpus had this shape: zero of
 * the 78 conformance fixtures declared a non-readonly `boolean` property.
 * (`property-initializers` has `active: boolean`, but it is `readonly` — a
 * constructor arg spliced into the script, not a state field.)
 *
 * The seven-tier comparison lives in `conformance/sdk-output/` and runs the
 * real SDKs. This file is its ANCHOR. Agreement alone is not a correctness
 * test — five tiers agreeing on `00` would have passed a peer-only check for
 * the `false` case — so the bytes are pinned here against the compiler's own
 * declared layout, independently of what any SDK emits. In particular, the
 * goldens must not be re-derivable by `sdk-runner --update-golden` from a
 * wrong TypeScript tier without this test going red.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { serializeState, deserializeState } from 'runar-sdk';
import type { StateField } from 'runar-ir-schema';

const REPO = resolve(__dirname, '..');
const FIXTURES = join(REPO, 'conformance/sdk-output/tests');

/** The `count` value both fixtures are built with, as NUM2BIN-8 little-endian. */
const COUNT_7_LE8 = '0700000000000000';

interface Fixture {
  artifact: {
    script: string;
    stateFields: StateField[];
  };
  constructorArgs: Array<{ type: string; value: string }>;
}

function loadFixture(name: string): { input: Fixture; golden: string } {
  const dir = join(FIXTURES, name);
  return {
    input: JSON.parse(readFileSync(join(dir, 'input.json'), 'utf-8')) as Fixture,
    golden: readFileSync(join(dir, 'expected-locking.hex'), 'utf-8').trim().toLowerCase(),
  };
}

const CASES: Array<{ fixture: string; flag: boolean; byte: string }> = [
  { fixture: 'stateful-boolean-true', flag: true, byte: '01' },
  { fixture: 'stateful-boolean-false', flag: false, byte: '00' },
];

describe('R-248: a mutable boolean state field is one raw byte', () => {
  it('the fixtures declare the canonical `boolean` spelling, not `bool`', () => {
    for (const { fixture } of CASES) {
      const { input } = loadFixture(fixture);
      const flag = input.artifact.stateFields.find((f) => f.name === 'flag');

      // If this ever reads `bool`, the fixture has stopped exercising the
      // spelling the compiler actually emits and the whole suite goes blind
      // again — which is exactly the state the corpus was in.
      expect(flag, `${fixture}: no 'flag' state field`).toBeDefined();
      expect(flag!.type, `${fixture}: flag type`).toBe('boolean');
      expect(flag!.encoding, `${fixture}: flag encoding`).toBe('bool1');
      expect(flag!.byteLength, `${fixture}: flag byte length`).toBe(1);
      expect(flag!.index, `${fixture}: flag must be the LAST field, so a wrong ` +
        'width shows up as a wrong total length').toBe(1);
    }
  });

  it.each(CASES)(
    'the $fixture golden ends in the single byte $byte',
    ({ fixture, byte }) => {
      const { input, golden } = loadFixture(fixture);
      const script = input.artifact.script.toLowerCase();

      // Built from the artifact, not from any SDK: <code part> OP_RETURN
      // <count:8> <flag:1>.
      const expected = `${script}6a${COUNT_7_LE8}${byte}`;

      expect(golden).toBe(expected);
      expect(golden.slice(script.length)).toBe(`6a${COUNT_7_LE8}${byte}`);
      // 8 + 1 state bytes after the separator. `02true` is 5, which is the
      // whole Go/Java defect in one number.
      expect((golden.length - script.length - 2) / 2).toBe(9);
    },
  );

  it.each(CASES)(
    'the TypeScript SDK serializes $fixture to that byte',
    ({ fixture, flag, byte }) => {
      const { input } = loadFixture(fixture);
      const hex = serializeState(input.artifact.stateFields, { count: 7n, flag });
      expect(hex).toBe(`${COUNT_7_LE8}${byte}`);
    },
  );

  it('round-trips both polarities through deserializeState', () => {
    const { input } = loadFixture('stateful-boolean-true');
    for (const flag of [true, false]) {
      const hex = serializeState(input.artifact.stateFields, { count: 7n, flag });
      const back = deserializeState(input.artifact.stateFields, hex);
      expect(back.flag, `flag=${flag}`).toBe(flag);
      expect(back.count, `flag=${flag}`).toBe(7n);
    }
  });

  it('accepts the `bool` alias too — some tiers already did, do not break them', () => {
    const fields = [
      { name: 'flag', type: 'bool', index: 0 },
    ] as unknown as StateField[];
    expect(serializeState(fields, { flag: true })).toBe('01');
    expect(serializeState(fields, { flag: false })).toBe('00');
    expect(deserializeState(fields, '01').flag).toBe(true);
    expect(deserializeState(fields, '00').flag).toBe(false);
  });
});
