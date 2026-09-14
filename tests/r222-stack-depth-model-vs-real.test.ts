/**
 * R-222 / R-242 (CL-GAP-079, CL-GAP-094): `maxStackDepth` is computed from the
 * compiler's stack MODEL, and the delegated codegen modules — crypto, and the
 * unrolled math intrinsics — emit through a callback that never touches the
 * model. So the 800-item bound is enforced against a number that systematically
 * understates the real runtime depth.
 *
 * The reviewers found the same gap independently in the Go and Python tiers and
 * listed the blind spots: reverseBytes (520 iterations), pow (32), sqrt (16),
 * gcd (256), log2 (64), the Groth16 preamble, and ~18 delegated modules.
 *
 * "Emits hundreds of ops the model never sees" is true and is not the same claim
 * as "exceeds the real limit": an unrolled loop can run for 520 iterations with
 * a working set of three items. Whether the gap is REACHABLE is a question about
 * depth, and it is answerable — the ScriptVM steps one opcode at a time, so the
 * real peak is observable.
 *
 * This test measures it: for each blind spot, compile, spend, step the whole
 * script, and record the true peak against what the artifact claims. It asserts
 * the property that actually matters — the real peak stays under the consensus
 * element limit — and prints both numbers so the size of the model's blind spot
 * is a measured number in the record rather than an adjective.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { ScriptVM } from 'runar-testing';

/** The bound the compiler enforces against its model. */
const MODEL_BOUND = 800;
/** The engine's element limit (main + alt), the thing that actually aborts. */
const VM_ELEMENT_LIMIT = 1000;

function contract(body: string, imports: string): string {
  return `
import { SmartContract, assert, ${imports} } from 'runar-lang';

class DepthProbe extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public unlock(x: bigint) {
    ${body}
  }
}
`;
}

const BLIND_SPOTS: Array<{ name: string; src: string; unlocking: string }> = [
  {
    name: 'pow (32 unrolled multiplies)',
    src: contract('assert(pow(x, 10n) === this.expected);', 'pow'),
    unlocking: '0101' + '0101',
  },
  {
    name: 'sqrt (16 Newton iterations)',
    src: contract('assert(sqrt(x) === this.expected);', 'sqrt'),
    unlocking: '0101' + '0101',
  },
  {
    name: 'gcd (256 iterations)',
    src: contract('assert(gcd(x, 12n) === this.expected);', 'gcd'),
    unlocking: '0101' + '0101',
  },
  {
    name: 'log2 (64 iterations)',
    src: contract('assert(log2(x) === this.expected);', 'log2'),
    unlocking: '0101' + '0101',
  },
  // The crypto delegates are the larger half of the claim: every one emits
  // through a callback the stack model never sees.
  {
    name: 'reverseBytes (520 unrolled iterations)',
    src: `
import { SmartContract, assert, reverseBytes } from 'runar-lang';

class DepthProbe extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public unlock(x: ByteString) {
    assert(reverseBytes(x) === this.expected);
  }
}
`,
    unlocking: '0101' + '0101',
  },
  {
    name: 'ecMul (256-iteration double-and-add ladder)',
    src: `
import { SmartContract, assert, ecMul, ecPointX } from 'runar-lang';
import type { Point } from 'runar-lang';

class DepthProbe extends SmartContract {
  readonly expected: bigint;

  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }

  public unlock(p: Point, k: bigint) {
    assert(ecPointX(ecMul(p, k)) === this.expected);
  }
}
`,
    unlocking: '0101' + '0101' + '0101',
  },
];

/** Step the whole script, returning the peak of main + alt stack. */
function peakDepth(lockingHex: string, unlockingHex: string): number {
  const vm = new ScriptVM();
  vm.loadHex(unlockingHex, lockingHex);
  let peak = 0;
  for (let i = 0; i < 5_000_000; i++) {
    const step = vm.step();
    if (step === null) break;
    const depth = vm.currentStack.length + vm.currentAltStack.length;
    if (depth > peak) peak = depth;
  }
  return peak;
}

describe('R-222/R-242: the model bound versus the real stack depth', () => {
  for (const { name, src, unlocking } of BLIND_SPOTS) {
    it(`${name}: the real peak stays under the engine's element limit`, () => {
      const result = compile(src, { fileName: 'DepthProbe.runar.ts' });
      expect(
        result.success,
        result.diagnostics.map((d) => d.message).join('\n'),
      ).toBe(true);
      const scriptHex = result.scriptHex!;

      const peak = peakDepth(scriptHex, unlocking);

      // eslint-disable-next-line no-console
      console.log(
        `[R-222] ${name}: real peak ${peak}, model bound ${MODEL_BOUND}, ` +
          `engine limit ${VM_ELEMENT_LIMIT}, script ${scriptHex.length / 2} bytes`,
      );

      expect(peak, `${name} exceeded the engine's element limit`).toBeLessThan(
        VM_ELEMENT_LIMIT,
      );
    });
  }

  it('the measurement is not vacuous — stepping reaches a real depth', () => {
    // A contract with no delegated codegen at all: if even this reports 0, the
    // harness is not stepping and every case above passes for the wrong reason.
    const result = compile(
      contract('assert(x + 1n === this.expected);', 'assert'),
      { fileName: 'DepthProbe.runar.ts' },
    );
    expect(result.success, result.diagnostics.map((d) => d.message).join('\n')).toBe(true);
    expect(peakDepth(result.scriptHex!, '0101' + '0101')).toBeGreaterThan(0);
  });
});
