/**
 * N-007 — a method parameter that shadows a MUTABLE property must stay the
 * parameter inside an `if` / ternary arm.
 *
 * Issue #130 (stack layer): `deserialize_state` pushes each mutable property
 * under its own name, so a same-named method parameter would lose every name
 * lookup to the (shallower) property slot. The `LoweringContext` constructor
 * renames that parameter's slot to `__param_<name>` and records the mapping in
 * `renamedParams`; `lowerLoadParam` resolves through that map.
 *
 * The defect: `lowerIf` lowers each arm in a FRESH `LoweringContext`. The arm's
 * stack is a clone of the parent's (so it carries the `__param_<name>` slot)
 * but its `renamedParams` started EMPTY. A `load_param` inside the arm looked
 * up the bare name and found the deserialized PROPERTY slot — the pre-call
 * on-chain state — instead of the caller's witness argument:
 *
 *     public set(count: bigint, flag: boolean) {
 *       if (flag) { assert(count == 5n); }     // arm read this.count (stale)
 *       this.count = count;
 *     }
 *
 * With on-chain `count = 5`, `set(7n, true)` satisfied a guard the source says
 * must fail — a FAIL-OPEN guard. TS, Go, Rust, Zig and Ruby all emitted those
 * bytes; Python was fixed by F-015 and Java's `subContext` already copied the
 * map. The real-engine proof is
 * `packages/runar-testing/src/__tests__/n007-param-shadow-branch-arm-vm.test.ts`,
 * and the corrected bytes are pinned cross-tier by the conformance fixture
 * `conformance/tests/param-shadow-branch-arm`.
 *
 * Oracle (needs no reference tier): a parameter's NAME is not part of the
 * program. Alpha-renaming the parameter to a non-colliding name
 * (`count` -> `newCount`) must compile to a byte-identical script.
 *
 * What this proves: TS stack lowering resolves a shadowing parameter to the
 * same slot inside an if-then arm, an if-else arm and a ternary arm as it does
 * for a non-colliding name, in both fold modes. What it does NOT prove: that
 * the renamed program itself is correct on-chain (the VM test above), or
 * anything about the other tiers (each has its own copy of this test).
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

const PRELUDE = `import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

`;

const THEN_ARM = `  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(count == 5n);
    }
    this.count = count;
  }
}
`;

const ELSE_ARM = `  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(flag);
    } else {
      assert(count > 10n);
    }
    this.count = count;
  }
}
`;

const TERNARY_ARM = `  public set(count: bigint, flag: boolean) {
    const v: bigint = flag ? count + 1n : 0n;
    assert(v != 3n);
    this.count = count;
  }
}
`;

// Control: the parameter is read only OUTSIDE any arm. This shape was already
// correct before the fix; it pins that the oracle is not vacuous.
const NO_ARM = `  public set(count: bigint, flag: boolean) {
    assert(count != 3n);
    assert(flag);
    this.count = count;
  }
}
`;

function alphaRename(body: string): string {
  return body
    .replace('set(count: bigint', 'set(newCount: bigint')
    .replace('this.count = count;', 'this.count = newCount;')
    .replace('(count ', '(newCount ')
    .replace('? count ', '? newCount ');
}

function compileHex(body: string, disableConstantFolding: boolean): string {
  const r = compile(PRELUDE + body, { fileName: 'Probe.runar.ts', disableConstantFolding });
  expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
  return r.artifact!.script;
}

describe('N-007: a property-shadowing param read inside a branch arm is the parameter', () => {
  const cases: [string, string][] = [
    ['then-arm', THEN_ARM],
    ['else-arm', ELSE_ARM],
    ['ternary-arm', TERNARY_ARM],
    ['control/no-arm', NO_ARM],
  ];

  for (const [label, body] of cases) {
    for (const disable of [true, false]) {
      it(`${label} (fold-${disable ? 'off' : 'on'}) compiles like the alpha-renamed program`, () => {
        const renamed = alphaRename(body);
        // The rename must actually have removed every read of the shadowing name.
        expect(renamed).not.toMatch(/(?<![.\w])count\b/);
        expect(
          compileHex(body, disable),
          `${label}: the arm read the deserialized state slot, not the witness argument`,
        ).toBe(compileHex(renamed, disable));
      });
    }
  }
});
