/**
 * currentBlockHeight() pins the locktime domain itself.
 *
 * Consensus reads an nLockTime >= 500000000 as a Unix timestamp. Before this
 * change `currentBlockHeight()` was bare sugar for
 * `extractLocktime(this.txPreimage)`, so `currentBlockHeight() >= H` passed
 * for any timestamp-domain locktime (spendable at once) unless the author
 * also wrote the `< 500000000n` bound D26 demanded. Now every call lowers to
 *   load_param txPreimage; call extractLocktime; load_const 500000000;
 *   bin_op <; assert
 * and yields the extractLocktime value, so the read is genuinely a height.
 * One pin per CALL (not per method): a pin hoisted to method entry would
 * refuse timestamp-locktime spends on paths that never read the height, and
 * one at the first use is unsound when that use sits in a branch.
 *
 * Proves: the exact ANF shape and order of one call; two calls give two pins;
 * the ANF interpreter path (TestContract) refuses a timestamp-domain locktime
 * and accepts a height; D26 no longer refuses `currentBlockHeight() >= H`, and
 * still refuses an unpinned `extractLocktime(p) >= H` and a local mixed from
 * both reads.
 * Does not prove: the other six compilers (conformance goldens +
 * locktime-domain-cases.json) or on-chain execution.
 */
import { describe, it, expect } from 'vitest';
import { compile, compileFromANF } from '../index.js';
import type { ANFBinding } from '../ir/index.js';
// @ts-expect-error vitest resolves this via alias (runar-testing is not a tsc dep of runar-compiler)
import { TestContract } from 'runar-testing';
// runar-testing is not a tsc dep of runar-compiler: load its oracle at run time
// through a non-literal specifier so tsc does not pull its sources into this
// package's build.
const ORACLE = new URL('../../../runar-testing/src/oracle/real-crypto-execution.ts', import.meta.url).href;
type SpendResult = { vmAccepted: boolean; vmError?: string };
const runStatefulSpend = async (opts: Record<string, unknown>): Promise<SpendResult> =>
  ((await import(/* @vite-ignore */ ORACLE)) as { runStatefulSpend: (o: Record<string, unknown>) => Promise<SpendResult> })
    .runStatefulSpend(opts);

const D26 = /compares extractLocktime against a lower bound without pinning the locktime domain/;

const gate = (body: string, helpers = '') => `import { StatefulSmartContract, assert, currentBlockHeight, extractLocktime, extractSequence } from 'runar-lang';
class G extends StatefulSmartContract {
  readonly h: bigint;
  count: bigint;
  constructor(h: bigint, count: bigint) { super(h, count); this.h = h; this.count = count; }
${helpers}
  public spend() {
    assert(extractSequence(this.txPreimage) !== 0xffffffffn);
${body}
    this.count = this.count + 1n;
  }
}
`;

function errorsOf(src: string): string[] {
  const r = compile(src, { fileName: 'G.runar.ts' });
  return r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
}

function spendBody(src: string): ANFBinding[] {
  const r = compile(src, { fileName: 'G.runar.ts', disableConstantFolding: true });
  expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
  return r.anf!.methods.find((m) => m.name === 'spend')!.body;
}

describe('currentBlockHeight() emits its own height-domain pin', () => {
  it('lowers to extractLocktime + assert(< 500000000) and yields the extractLocktime value', () => {
    const body = spendBody(gate('    assert(currentBlockHeight() >= this.h);'));
    const i = body.findIndex((b) => b.value.kind === 'call' && b.value.func === 'extractLocktime');
    expect(i).toBeGreaterThan(0);
    const [pre, call, lit, lt, pin] = body.slice(i - 1, i + 4);
    expect(pre!.value).toEqual({ kind: 'load_param', name: 'txPreimage' });
    expect(call!.value).toEqual({ kind: 'call', func: 'extractLocktime', args: [pre!.name] });
    expect(lit!.value).toEqual({ kind: 'load_const', value: 500000000n });
    expect(lt!.value).toEqual({ kind: 'bin_op', op: '<', left: call!.name, right: lit!.name });
    expect(pin!.value).toEqual({ kind: 'assert', value: lt!.name });
    // The user's compare reads the extractLocktime binding, not the pin.
    const ge = body.find((b) => b.value.kind === 'bin_op' && b.value.op === '>=');
    expect(ge && ge.value.kind === 'bin_op' && ge.value.left).toBe(call!.name);
  });

  // Private helpers are inlined. The preimage must resolve as `this.txPreimage`
  // does in a helper (load_prop, which the stack lowerer copies): a
  // load_param there was the helper's own last use of the caller's preimage,
  // so it was consumed and the caller's continuation read failed ("method
  // parameter 'txPreimage' is not on the stack").
  it('in a private helper the preimage read resolves as this.txPreimage does', () => {
    const HEIGHT = '  private height(): bigint {\n    return currentBlockHeight();\n  }\n';
    const r = compile(gate('    assert(this.height() >= this.h);', HEIGHT), { fileName: 'G.runar.ts', disableConstantFolding: true });
    expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
    const helper = r.anf!.methods.find((m) => m.name === 'height')!.body;
    const raw = compile(
      gate('    assert(this.height() >= this.h);', '  private height(): bigint {\n    const lt = extractLocktime(this.txPreimage);\n    assert(lt < 500000000n);\n    return lt;\n  }\n'),
      { fileName: 'G.runar.ts', disableConstantFolding: true },
    ).anf!.methods.find((m) => m.name === 'height')!.body;
    expect(helper[0]!.value).toEqual(raw[0]!.value);
    expect(helper[0]!.value).toEqual({ kind: 'load_prop', name: 'txPreimage' });
    expect(helper.slice(1, 5).map((b) => b.value.kind)).toEqual(['call', 'load_const', 'bin_op', 'assert']);
  });

  it('one pin per call', () => {
    const body = spendBody(gate('    assert(currentBlockHeight() >= this.h);\n    assert(currentBlockHeight() <= this.h + 100n);'));
    const pins = body.filter((b) => b.value.kind === 'bin_op' && b.value.op === '<' && body.some(
      (c) => c.name === (b.value as { right: string }).right && c.value.kind === 'load_const' && c.value.value === 500000000n,
    ));
    expect(pins.length).toBe(2);
  });

  it('D26 accepts a currentBlockHeight() lower bound with no explicit pin', () => {
    expect(errorsOf(gate('    assert(currentBlockHeight() >= this.h);'))).toEqual([]);
    expect(errorsOf(gate('    const now = currentBlockHeight();\n    assert(now > this.h);'))).toEqual([]);
  });

  it('D26 still refuses an unpinned extractLocktime gate and a mixed local', () => {
    expect(errorsOf(gate('    assert(extractLocktime(this.txPreimage) >= this.h);')).join('\n')).toMatch(D26);
    expect(
      errorsOf(gate('    let lt = currentBlockHeight();\n    if (this.h > 5n) { lt = extractLocktime(this.txPreimage); }\n    assert(lt >= this.h);')).join('\n'),
    ).toMatch(D26);
  });

  it('TestContract refuses a timestamp-domain locktime and accepts a height', () => {
    const src = gate('    assert(currentBlockHeight() >= this.h);');
    const ok = TestContract.fromSource(src, { h: 100n, count: 0n }, 'G.runar.ts');
    ok.setMockPreimage({ locktime: 499_999_999n, sequence: 0xfffffffen });
    expect(ok.call('spend').success).toBe(true);
    const ts = TestContract.fromSource(src, { h: 100n, count: 0n }, 'G.runar.ts');
    ts.setMockPreimage({ locktime: 500_000_000n, sequence: 0xfffffffen });
    const r = ts.call('spend');
    expect(r.success).toBe(false);
    expect(r.error).toMatch(/currentBlockHeight/);
  });

  it('TestContract runs a helper and a ternary arm: timestamp refused, height accepted', () => {
    const HELPERS =
      '  private height(): bigint {\n    return currentBlockHeight();\n  }\n' +
      '  private pick(): bigint {\n    return this.count > 5n ? currentBlockHeight() : 1000n;\n  }\n';
    for (const body of ['    assert(this.height() >= this.h);', '    assert(this.pick() >= this.h);']) {
      const src = gate(body, HELPERS);
      const ok = TestContract.fromSource(src, { h: 100n, count: 10n }, 'G.runar.ts');
      ok.setMockPreimage({ locktime: 499_999_999n, sequence: 0xfffffffen });
      expect(ok.call('spend').success, body).toBe(true);
      const ts = TestContract.fromSource(src, { h: 100n, count: 10n }, 'G.runar.ts');
      ts.setMockPreimage({ locktime: 500_000_000n, sequence: 0xfffffffen });
      expect(ts.call('spend').success, body).toBe(false);
    }
  });

  it('refuses a currentBlockHeight() compare against a timestamp literal (it could never pass)', () => {
    const CBH_TS = /compares currentBlockHeight\(\) against a Unix-timestamp bound/;
    for (const body of [
      '    assert(currentBlockHeight() >= 500000000n);',
      '    assert(currentBlockHeight() > 499999999n);',
      '    assert(1700000000n <= currentBlockHeight());',
      '    assert(600000000n < currentBlockHeight());',
      '    if (currentBlockHeight() >= 1700000000n) { this.count = 0n; }',
      '    const now = currentBlockHeight();\n    assert(now >= 1700000000n);',
      '    let now = currentBlockHeight();\n    now = currentBlockHeight();\n    assert(500000000n <= now);',
    ]) {
      expect(errorsOf(gate(body)).join('\n'), body).toMatch(CBH_TS);
    }
    for (const body of [
      '    assert(currentBlockHeight() >= 499999999n);',
      '    assert(currentBlockHeight() > 499999998n);',
      '    assert(currentBlockHeight() < 600000000n);',
      '    assert(extractLocktime(this.txPreimage) >= 1700000000n);',
      '    let now = currentBlockHeight();\n    now = this.h;\n    assert(now >= 1700000000n);',
    ]) {
      expect(errorsOf(gate(body)).join('\n'), body).not.toMatch(CBH_TS);
    }
  });

  // A helper call AFTER the caller's last own preimage read (a terminal method
  // with no state write): the inlined helper's read is a use of the caller's
  // slot at the call, so the slot is not consumed before it. It used to fail
  // in all seven tiers ("property 'txPreimage' ... is neither on the stack"),
  // for currentBlockHeight() and for a hand-written this.txPreimage read alike.
  describe('executed: terminal method whose last preimage read is in a helper', () => {
    const terminal = (helper: string, body: string) => `import { StatefulSmartContract, assert, currentBlockHeight, extractLocktime, extractSequence } from 'runar-lang';
class T extends StatefulSmartContract {
  readonly h: bigint;
  count: bigint;
  constructor(h: bigint, count: bigint) { super(h, count); this.h = h; this.count = count; }
${helper}
  public close(flag: boolean) {
    assert(extractSequence(this.txPreimage) !== 0xffffffffn);
${body}
  }
}
`;
    const CBH = '  private height(): bigint {\n    return currentBlockHeight();\n  }';
    const RAW = '  private height(): bigint {\n    const lt = extractLocktime(this.txPreimage);\n    assert(lt < 500000000n);\n    return lt;\n  }';
    const shapes: Array<[string, string, string]> = [
      ['currentBlockHeight-helper', CBH, '    assert(this.height() >= this.h);'],
      ['this.txPreimage-helper', RAW, '    assert(this.height() >= this.h);'],
      ['helper-in-one-arm', CBH, '    if (flag) {\n      assert(this.height() >= this.h);\n    } else {\n      assert(this.h > 0n);\n    }'],
      ['helper-in-loop', CBH, '    for (let i = 0n; i < 2n; i++) {\n      assert(this.height() >= this.h + i);\n    }\n    assert(this.h > 0n);'],
    ];
    for (const [name, helper, body] of shapes) {
      for (const [lockTime, ok] of [[499_999_999, true], [500_000_000, false]] as const) {
        it(`${name} @ nLockTime ${lockTime} -> ${ok ? 'accept' : 'reject'}`, async () => {
          const res = await runStatefulSpend({
            source: terminal(helper, body),
            fileName: 'T.runar.ts',
            method: 'close',
            args: [true],
            constructorArgs: [100n, 10n],
            signerKey: 'alice',
            lockTime,
          });
          expect(res.vmAccepted, res.vmError ?? '').toBe(ok);
        });
      }
    }
  });

  // The --ir path may spell a helper's preimage read `load_param txPreimage`
  // (D25's helper outpoint binding does; the Lean model's WF admits both). It
  // compiles too: a caller-scope slot the caller reads again after the call is
  // protected inside the helper (copied), as lowerIf protects a ref still
  // needed after an `if`; so with a later caller read it is byte-identical to
  // the load_prop spelling, and as the caller's last use it is consumed there.
  it('a helper reading the caller preimage as load_param compiles (--ir input)', () => {
    const HEIGHT = '  private height(): bigint {\n    return currentBlockHeight();\n  }\n';
    const respell = (src: string, fileName: string): { asProp: string; asParam: string } => {
      const r = compile(src, { fileName, disableConstantFolding: true });
      expect(r.diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
      const asProp = compileFromANF(r.anf!, { disableConstantFolding: true }).scriptHex;
      const anf = structuredClone(r.anf!);
      const helper = anf.methods.find((m) => m.name === 'height')!;
      expect(helper.body[0]!.value).toEqual({ kind: 'load_prop', name: 'txPreimage' });
      helper.body[0]!.value = { kind: 'load_param', name: 'txPreimage' };
      return { asProp, asParam: compileFromANF(anf, { disableConstantFolding: true }).scriptHex };
    };
    const later = respell(gate('    assert(this.height() >= this.h);', HEIGHT), 'G.runar.ts');
    expect(later.asParam).toBe(later.asProp);
    const last = respell(
      `import { StatefulSmartContract, assert, currentBlockHeight } from 'runar-lang';
class T extends StatefulSmartContract {
  readonly h: bigint;
  count: bigint;
  constructor(h: bigint, count: bigint) { super(h, count); this.h = h; this.count = count; }
${HEIGHT}
  public close() {
    assert(this.height() >= this.h);
  }
}
`,
      'T.runar.ts',
    );
    expect(last.asParam.length).toBeGreaterThan(0);
  });

  // Executed on the @bsv/sdk Spend engine (real checkPreimage continuation):
  // the pin holds wherever the call sits, including inside a value-producing
  // arm (the right of &&, a ternary arm) and an if arm; a height spend passes.
  describe('executed: nLockTime 499999999 passes, 500000000 is refused', () => {
    const shapes: Array<[string, string]> = [
      ['statement', '    assert(currentBlockHeight() >= this.h);'],
      ['rhs-of-and', '    assert(this.count >= 0n && currentBlockHeight() >= this.h);'],
      ['ternary-arm', '    assert((this.count > 5n ? currentBlockHeight() : 1000n) >= this.h);'],
      ['if-arm', '    if (this.count > 5n) {\n      assert(currentBlockHeight() >= this.h);\n    }'],
      ['two-calls', '    assert(currentBlockHeight() >= this.h);\n    assert(currentBlockHeight() <= this.h + 600000000n);'],
      ['helper', '    assert(this.height() >= this.h);'],
      ['ternary-in-helper', '    assert(this.pick() >= this.h);'],
    ];
    const HELPERS =
      '  private height(): bigint {\n    return currentBlockHeight();\n  }\n' +
      '  private pick(): bigint {\n    return this.count > 5n ? currentBlockHeight() : 1000n;\n  }\n';
    for (const [name, body] of shapes) {
      for (const [lockTime, ok] of [[499_999_999, true], [500_000_000, false]] as const) {
        it(`${name} @ nLockTime ${lockTime} -> ${ok ? 'accept' : 'reject'}`, async () => {
          const res = await runStatefulSpend({
            source: gate(body, HELPERS),
            fileName: 'G.runar.ts',
            method: 'spend',
            args: [],
            constructorArgs: [100n, 10n],
            signerKey: 'alice',
            lockTime,
          });
          expect(res.vmAccepted, res.vmError ?? "").toBe(ok);
        });
      }
    }
  });
});
