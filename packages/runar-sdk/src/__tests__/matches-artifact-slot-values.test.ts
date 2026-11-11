/**
 * matchesArtifact must check what sits at each constructor slot, not only the
 * template bytes between slots.
 *
 * RunarContract writes encodeArg(value) at every constructor slot of a param:
 * a push or a small-integer opcode, the same bytes at every reference of the
 * param, and exactly fixedValueByteLength bytes where the slot declares one.
 * matchesArtifact compared the template bytes around the slots but took any
 * element at a slot, so it returned true for scripts no deployment produces,
 * and extractConstructorArgs then reported arguments that do not describe the
 * script (only the first reference of a param, or for a non-push opcode a
 * value the script does not hold: '', 0n or true by type).
 * A stateful contract is deployed with an OP_RETURN and its state after the
 * code part, but a stateful artifact's code part alone also matched.
 *
 * Replays the shared vector conformance/sdk-matches-artifact/slot-values.json:
 * a synthetic artifact with one PubKey param referenced twice, one with a
 * 1-byte fixed-width slot (an OP_N value counts as one byte), and the
 * compiler-produced SlotMatrix artifact, honest = RunarContract.getLockingScript()
 * (including ByteStrings that bake as OP_N, OP_1NEGATE and OP_0), plus two
 * small stateful artifacts (one with slots, one slot-free).
 *
 * Proves: honest deployments still match; a non-push opcode at a constructor
 * slot, different bytes at two references of one param, and a push of the
 * wrong width at a fixed-width slot do not; a stateful artifact's script with
 * no OP_RETURN after its code part does not; hex case inside a slot value does
 * not matter; extractConstructorArgs refuses a non-push opcode at any
 * reference of a param; extractConstructorArgs reads a constructor arg from
 * its deployed position after a codeSepIndex slot whose baked value is wider
 * than one byte.
 * Does NOT prove: anything about the Go, Rust, Python, Zig, Ruby or Java
 * SDKs, which replay the vector in their own tests; nor that a slot push is
 * minimally encoded; nor that extractConstructorArgs validates anything
 * beyond the non-push refusal (call matchesArtifact first); nor anything
 * about the length of the state after the OP_RETURN.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractConstructorArgs, matchesArtifact } from '../script-utils.js';
import { RunarContract } from '../contract.js';
import { MalformedScriptError } from '../errors.js';
import type { RunarArtifact } from '../types.js';

const fixture = JSON.parse(
  readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-matches-artifact/slot-values.json'),
    'utf8',
  ),
) as {
  artifacts: Record<string, RunarArtifact>;
  cases: { name: string; artifact: string; script_hex: string; expected: boolean }[];
};

const G = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const owner2 = fixture.artifacts.owner2!;
const slotMatrix = fixture.artifacts.slotMatrix!;

describe('matchesArtifact checks the element at every constructor slot (slot-values.json)', () => {
  for (const c of fixture.cases) {
    it(c.name, () => {
      expect(matchesArtifact(fixture.artifacts[c.artifact]!, c.script_hex)).toBe(c.expected);
    });
  }
});

describe('matchesArtifact: slot values compare without regard to hex case', () => {
  it('a repeated param with the value in upper case at one reference', () => {
    expect(matchesArtifact(owner2, `21${G}ad21${G.toUpperCase()}ac`)).toBe(true);
  });
});

describe('extractConstructorArgs refuses a non-push opcode at a constructor slot', () => {
  it('at the first reference of a param', () => {
    expect(() => extractConstructorArgs(owner2, `acad21${G}ac`)).toThrow(MalformedScriptError);
  });

  it('at a later reference of a param whose first reference was already read', () => {
    expect(() => extractConstructorArgs(owner2, `21${G}adacac`)).toThrow(MalformedScriptError);
  });

  it('on SlotMatrix', () => {
    const script = 'ac7b880111' + '7c9dac' + `21${G}879169` + `21${G}ac`;
    expect(() => extractConstructorArgs(slotMatrix, script)).toThrow(MalformedScriptError);
  });

  it('honest deployments still extract', () => {
    for (const c of fixture.cases.filter((x) => x.expected && x.artifact === 'slotMatrix')) {
      expect(extractConstructorArgs(slotMatrix, c.script_hex)).toMatchObject({ count: 17n, owner: G });
    }
    expect(extractConstructorArgs(owner2, fixture.cases.find((x) => x.name === 'owner2-honest')!.script_hex))
      .toEqual({ owner: G });
  });
});

describe('extractConstructorArgs after a codeSepIndex slot', () => {
  // Hand-built: a codeSepIndex slot at byte 1 with codeSepIndex 140, baked as
  // 143 (`02 8f00`: 140 plus the 3-byte growth of the constructor slot before
  // index 140), then a constructor slot at byte 3. The TS compiler emits
  // codeSep slots before constructor slots, but with codeSepIndex 1 (a 1-byte
  // OP_1), so its output never shifts the constructor slot this way.
  const cs = {
    version: 'runar-v1.0.0-rc.1',
    compilerVersion: '1.0.0-rc.1',
    contractName: 'CodeSepBeforeSlot',
    asm: '',
    buildTimestamp: '',
    abi: { constructor: { params: [{ name: 'x', type: 'ByteString' }] }, methods: [] },
    script: '5100520053',
    constructorSlots: [{ paramIndex: 0, byteOffset: 3 }],
    codeSepIndexSlots: [{ byteOffset: 1, codeSepIndex: 140 }],
  } as unknown as RunarArtifact;

  it('reads the constructor arg from its deployed position', () => {
    const script = new RunarContract(cs, ['aabbcc']).getLockingScript();
    expect(script).toBe('51028f005203aabbcc53');
    expect(matchesArtifact(cs, script)).toBe(true);
    expect(extractConstructorArgs(cs, script)).toEqual({ x: 'aabbcc' });
  });
});
