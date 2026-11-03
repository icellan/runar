import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-046 (ScopeSnatcher) + N-047 (ShadowGoblin) — a block-scoped declaration,
 * or a local of an inlined private helper, that reuses a name already bound in
 * an enclosing scope must get its own ANF identity (user decision R24:
 * alpha-rename).
 *
 *     let authorized = checkSig(sig, this.owner);
 *     if (trigger) { let authorized = true; }   // a NEW variable
 *     assert(authorized);                       // must still test checkSig
 *
 * compiled with the inner `let` bound under the source name `authorized`, and
 * the if-arm reconciliation treated it as a reassignment of the outer local:
 * `assert` tested `true`, and any signature unlocked the coins. An inlined
 * output-emitting helper's `const valid = …` overwrote the caller's
 * `const valid = checkSig(…)` the same way.
 *
 * Oracle: alpha-equivalence, derived from the source language and not from
 * any compiler output. Renaming the inner declaration to a fresh name cannot
 * change what the program means, so the shadowing spelling must compile to
 * exactly the bytes of the renamed spelling ($L = the outer name vs $L = a
 * fresh name). Checked in both constant-folding modes.
 *
 * What this proves: in the TS reference, an inner `let` in a no-else if-arm,
 * in both arms of an if/else, in a nested if, in a loop body, a loop variable
 * that reuses an outer local's name, an inner `let` reusing a parameter's name,
 * a local of an inlined output-emitting helper reusing a caller local's or a
 * caller parameter's name, and an inner re-declaration that is itself
 * reassigned, all compile like their renamed spellings; and the renamed ANF
 * binding is `<name>@<n>`, distinct from the outer one.
 * What it does NOT prove: on-chain behaviour (the Spend.validate proof,
 * all seven tiers, is packages/runar-testing/src/__tests__/n046-block-scope-spend.test.ts),
 * nor the other six tiers (their own n046 unit tests cover them).
 */

const VAULT = (body: string) => `
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class ShadowVault extends SmartContract {
  readonly owner: PubKey;

  constructor(owner: PubKey) {
    super(owner);
    this.owner = owner;
  }

${body}
}
`;

const PAYOUT = (body: string) => `
import { StatefulSmartContract, ByteString, PubKey, Sig, assert, checkSig, len } from 'runar-lang';

class OwnerPayout extends StatefulSmartContract {
  nonce: bigint;
  readonly owner: PubKey;

  constructor(nonce: bigint, owner: PubKey) {
    super(nonce, owner);
    this.nonce = nonce;
    this.owner = owner;
  }

${body}
}
`;

/** `$L` is the inner declaration: the outer name when shadowing, `fresh` in the control. */
const SHAPES: Record<string, { template: string; outer: string }> = {
  'ScopeSnatcher: inner let in a no-else if-arm': {
    outer: 'authorized',
    template: VAULT(`  public spend(sig: Sig, trigger: boolean) {
    let authorized = checkSig(sig, this.owner);
    if (trigger) {
      let $L = true;
    }
    assert(authorized);
  }`),
  },
  'ScopeSnatcher: inner const in both arms of an if/else': {
    outer: 'ok',
    template: VAULT(`  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      const $L = true;
      assert($L);
    } else {
      const $L = x < 0n;
      assert(!$L);
    }
    assert(ok);
  }`),
  },
  'inner let in a nested if, read and reassigned inside its scope': {
    outer: 'ok',
    template: VAULT(`  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    if (x > 0n) {
      if (x > 1n) {
        let $L = x > 5n;
        $L = !$L;
        assert($L || x == 7n);
      }
    }
    assert(ok);
  }`),
  },
  'inner let in a loop body': {
    outer: 'ok',
    template: VAULT(`  public spend(sig: Sig, x: bigint) {
    let ok = checkSig(sig, this.owner);
    for (let i = 0n; i < 2n; i++) {
      let $L = x > i;
      assert($L);
    }
    assert(ok);
  }`),
  },
  'loop variable reusing an outer local name': {
    outer: 'i',
    template: VAULT(`  public spend(sig: Sig, x: bigint) {
    let i = x;
    let acc = 0n;
    for (let $L = 0n; $L < 3n; $L++) {
      acc = acc + $L;
    }
    assert(i == acc);
    assert(checkSig(sig, this.owner));
  }`),
  },
  'inner let reusing a parameter name': {
    outer: 'x',
    template: VAULT(`  public spend(sig: Sig, x: bigint) {
    if (x > 0n) {
      let $L = 5n;
      assert($L == 5n);
    }
    assert(x == 7n);
    assert(checkSig(sig, this.owner));
  }`),
  },
  'ShadowGoblin: inlined helper local reusing a caller local name': {
    outer: 'valid',
    template: PAYOUT(`  public withdraw(sig: Sig, destination: ByteString) {
    const valid = checkSig(sig, this.owner);
    this.pay(destination);
    assert(valid);
  }

  private pay(destination: ByteString) {
    const $L = len(destination) > 0n;
    assert($L);
    this.addRawOutput(50000n, destination);
  }`),
  },
  'inlined helper local reusing a caller parameter name': {
    outer: 'sig',
    template: PAYOUT(`  public withdraw(sig: Sig, destination: ByteString) {
    this.pay(destination);
    assert(checkSig(sig, this.owner));
  }

  private pay(destination: ByteString) {
    const $L = len(destination);
    assert($L > 0n);
    this.addRawOutput(50000n, destination);
  }`),
  },
};

function compileOk(source: string, disableConstantFolding: boolean) {
  const r = compile(source, { fileName: 'Shadow.runar.ts', disableConstantFolding });
  const errors = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
  expect(errors, 'compile errors').toEqual([]);
  expect(r.success).toBe(true);
  return r;
}

/** Every binding name in a (nested) ANF binding list. */
function bindingNames(bindings: { name: string; value: Record<string, unknown> }[]): string[] {
  const out: string[] = [];
  for (const b of bindings) {
    out.push(b.name);
    for (const k of ['then', 'else', 'body'] as const) {
      const nested = b.value[k];
      if (Array.isArray(nested)) out.push(...bindingNames(nested as never));
    }
  }
  return out;
}

describe('N-046 / N-047 — a shadowing declaration gets its own ANF identity', () => {
  for (const [name, { template, outer }] of Object.entries(SHAPES)) {
    for (const disableConstantFolding of [true, false]) {
      it(`${name} (fold ${disableConstantFolding ? 'off' : 'on'}) compiles like the renamed spelling`, () => {
        const shadow = compileOk(template.replaceAll('$L', outer), disableConstantFolding);
        const control = compileOk(template.replaceAll('$L', 'fresh'), disableConstantFolding);
        expect(shadow.artifact!.script).toBe(control.artifact!.script);
      });
    }
  }

  it('the ScopeSnatcher arm binds `authorized@1`, not the outer `authorized`', () => {
    const r = compileOk(SHAPES['ScopeSnatcher: inner let in a no-else if-arm']!.template.replaceAll('$L', 'authorized'), true);
    const spend = r.anf!.methods.find((m) => m.name === 'spend')!;
    const ifBinding = spend.body.find((b) => b.value.kind === 'if')!;
    const thenNames = bindingNames((ifBinding.value as unknown as { then: never[] }).then);
    expect(thenNames).toContain('authorized@1');
    expect(thenNames).not.toContain('authorized');
  });

  it('the ShadowGoblin helper local binds `valid@1` next to the caller\'s `valid`', () => {
    const r = compileOk(SHAPES['ShadowGoblin: inlined helper local reusing a caller local name']!.template.replaceAll('$L', 'valid'), true);
    const names = bindingNames(r.anf!.methods.find((m) => m.name === 'withdraw')!.body as never);
    expect(names.filter((n) => n === 'valid')).toHaveLength(1);
    expect(names).toContain('valid@1');
  });

  it('a program without shadowing keeps its source names (no rename when nothing collides)', () => {
    const r = compileOk(SHAPES['ScopeSnatcher: inner let in a no-else if-arm']!.template.replaceAll('$L', 'fresh'), true);
    const names = bindingNames(r.anf!.methods.find((m) => m.name === 'spend')!.body as never);
    expect(names).toContain('authorized');
    expect(names).toContain('fresh');
    expect(names.some((n) => n.includes('@'))).toBe(false);
  });

  // Python is function-scoped: `x = …` of a local the method already bound is
  // an ASSIGNMENT (the parser now says so), never a block-scoped shadow, so the
  // alpha-rename must not reach it. Pinned against the explicit TS spelling.
  it('Python surface: rebinding an outer local in a loop body and an if-arm stays an assignment', () => {
    const py = `from runar import SmartContract, Bigint, public, assert_

class Acc(SmartContract):
    expected: Bigint

    def __init__(self, expected: Bigint):
        super().__init__(expected)
        self.expected = expected

    @public
    def verify(self, start: Bigint):
        total: Bigint = 0
        for i in range(3):
            total = total + start + i
        if start > 0:
            total = total + 1
        assert_(total == self.expected)
`;
    const ts = `import { SmartContract, assert } from 'runar-lang';

class Acc extends SmartContract {
  readonly expected: bigint;
  constructor(expected: bigint) {
    super(expected);
    this.expected = expected;
  }
  public verify(start: bigint) {
    let total: bigint = 0n;
    for (let i = 0n; i < 3n; i++) {
      total = total + start + i;
    }
    if (start > 0n) {
      total = total + 1n;
    }
    assert(total == this.expected);
  }
}
`;
    for (const disableConstantFolding of [true, false]) {
      const p = compile(py, { fileName: 'Acc.runar.py', disableConstantFolding });
      const t = compile(ts, { fileName: 'Acc.runar.ts', disableConstantFolding });
      expect(p.success, JSON.stringify(p.diagnostics)).toBe(true);
      expect(t.success, JSON.stringify(t.diagnostics)).toBe(true);
      expect(p.artifact!.script).toBe(t.artifact!.script);
    }
  });
});
