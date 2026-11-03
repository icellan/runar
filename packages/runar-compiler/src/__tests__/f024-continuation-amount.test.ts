// ---------------------------------------------------------------------------
// F-024 (CL-BUG-079, user decision R14) — the default single-output state
// continuation must conserve the input value, and authors get a read-only
// view of the continuation amount.
//
// What this proves (TS tier, TS surface):
//   * every default single-output continuation (a public stateful method that
//     mutates state or emits a data output and never calls addOutput /
//     addRawOutput) carries the injected ANF
//       load_param txPreimage; call extractAmount; load_param _newAmount;
//       bin_op >= (_newAmount, amount); assert
//     after the method body and before the continuation output is built;
//   * addOutput methods and terminal methods do NOT get it;
//   * `continuationAmount()` lowers to `load_param _newAmount` where that
//     witness exists, and is refused everywhere else (stateless contracts,
//     terminal methods, addOutput methods, private helpers);
//   * a write to it is refused.
// What this does NOT prove: that the emitted script rejects a drain on-chain
// (packages/runar-testing/src/__tests__/f024-stateful-value-drain.test.ts
// does that with @bsv/sdk Spend), or cross-tier byte parity (conformance).
// ---------------------------------------------------------------------------

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';
import { CONTINUATION_AMOUNT_UNAVAILABLE } from '../passes/04-anf-lower.js';
const CONTINUATION_AMOUNT_READ_ONLY = 'continuationAmount() is read-only and cannot be assigned';
import type { ANFBinding, ANFMethod, ANFProgram } from '../ir/index.js';

function compileOk(source: string): ANFProgram {
  const r = compile(source, { fileName: 'C.runar.ts', disableConstantFolding: true });
  if (!r.success || !r.anf) {
    throw new Error(`compile failed: ${r.diagnostics.map(d => d.message).join(' | ')}`);
  }
  return r.anf;
}

function compileErrors(source: string): string[] {
  const r = compile(source, { fileName: 'C.runar.ts', disableConstantFolding: true });
  expect(r.success, 'expected the compile to fail').toBe(false);
  return r.diagnostics.filter(d => d.severity === 'error').map(d => d.message);
}

function method(p: ANFProgram, name: string): ANFMethod {
  const m = p.methods.find(x => x.name === name && x.isPublic);
  if (!m) throw new Error(`no public method ${name}`);
  return m;
}

/** Index of the injected `_newAmount >= extractAmount(txPreimage)` check, or -1. */
function injectedCheckAt(body: ANFBinding[]): number[] {
  const hits: number[] = [];
  for (let i = 0; i + 4 < body.length; i++) {
    const [a, b, c, d, e] = body.slice(i, i + 5) as [ANFBinding, ANFBinding, ANFBinding, ANFBinding, ANFBinding];
    if (
      a.value.kind === 'load_param' && a.value.name === 'txPreimage' &&
      b.value.kind === 'call' && b.value.func === 'extractAmount' &&
      b.value.args.length === 1 && b.value.args[0] === a.name &&
      c.value.kind === 'load_param' && c.value.name === '_newAmount' &&
      d.value.kind === 'bin_op' && d.value.op === '>=' &&
      d.value.left === c.name && d.value.right === b.name &&
      e.value.kind === 'assert' && e.value.value === d.name
    ) hits.push(i);
  }
  return hits;
}

function kindsOf(body: ANFBinding[]): string[] {
  return body.map(b => (b.value.kind === 'call' ? `call:${b.value.func}` : b.value.kind));
}

const COUNTER = `
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count = this.count + 1n; }
  public addTo(amount: bigint) { this.addOutput(1000n, this.count + amount); }
  public close() { assert(this.count > 0n); }
  public log(payload: ByteString) { this.addDataOutput(0n, payload); }
}
`;

describe('F-024 injected value-conservation check (TS tier)', () => {
  const anf = compileOk(COUNTER);

  it('a state-mutating default continuation carries exactly one check, after the body and before the continuation output', () => {
    const body = method(anf, 'increment').body;
    const hits = injectedCheckAt(body);
    expect(hits).toHaveLength(1);
    const at = hits[0]!;
    const kinds = kindsOf(body);
    // The method body (update_prop) precedes it ...
    expect(kinds.slice(0, at)).toContain('update_prop');
    // ... and the change output, the state output and the hash check follow it.
    const after = kinds.slice(at + 5);
    expect(after).toContain('get_state_script');
    expect(after).toContain('call:computeStateOutput');
    expect(after.indexOf('if')).toBeGreaterThanOrEqual(0);
    // The new assert is an ordinary assert: the off-chain interpreters must
    // evaluate it, not skip it as the on-chain-only hashOutputs check.
    const assertBinding = body[at + 4]!;
    expect((assertBinding.value as { isAutoInjectedStateCheck?: boolean }).isAutoInjectedStateCheck).toBeUndefined();
  });

  it('a data-output-only method keeps the default continuation, so it gets the check too', () => {
    expect(injectedCheckAt(method(anf, 'log').body)).toHaveLength(1);
  });

  it('an addOutput method sizes its own outputs: no _newAmount, no check', () => {
    const m = method(anf, 'addTo');
    expect(m.params.map(p => p.name)).not.toContain('_newAmount');
    expect(kindsOf(m.body)).not.toContain('call:extractAmount');
  });

  it('a terminal method has no continuation: no _newAmount, no check', () => {
    const m = method(anf, 'close');
    expect(m.params.map(p => p.name)).not.toContain('_newAmount');
    expect(kindsOf(m.body)).not.toContain('call:extractAmount');
  });
});

describe('F-024 continuationAmount() — read-only view of _newAmount (TS tier)', () => {
  it('a read lowers to load_param _newAmount and compiles', () => {
    const anf = compileOk(`
class Pot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public join(bet: bigint) {
    assert(continuationAmount() == extractAmount(this.txPreimage) + bet);
    this.count = this.count + 1n;
  }
}
`);
    const body = method(anf, 'join').body;
    // The author's read comes BEFORE the injected check, so it is its own load.
    const firstNewAmount = body.findIndex(b => b.value.kind === 'load_param' && b.value.name === '_newAmount');
    expect(firstNewAmount).toBeGreaterThanOrEqual(0);
    expect(firstNewAmount).toBeLessThan(injectedCheckAt(body)[0]!);
    expect(injectedCheckAt(body)).toHaveLength(1);
  });

  it('a write is refused', () => {
    const errs = compileErrors(`
class Pot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public join() {
    continuationAmount() = 5n;
    this.count = this.count + 1n;
  }
}
`);
    expect(errs).toContain(CONTINUATION_AMOUNT_READ_ONLY);
  });

  it('an increment of it is refused too', () => {
    const errs = compileErrors(`
class Pot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public join() {
    continuationAmount()++;
    this.count = this.count + 1n;
  }
}
`);
    expect(errs).toContain(CONTINUATION_AMOUNT_READ_ONLY);
  });

  it('is refused in a stateless contract', () => {
    const errs = compileErrors(`
class P extends SmartContract {
  readonly x: bigint;
  constructor(x: bigint) { super(x); this.x = x; }
  public unlock() { assert(continuationAmount() > this.x); }
}
`);
    expect(errs.join(' | ')).toContain('continuationAmount() is only available in StatefulSmartContract methods');
  });

  for (const [what, body] of [
    ['a terminal method', 'public close() { assert(continuationAmount() > 0n); }'],
    ['an addOutput method', 'public split() { this.addOutput(continuationAmount(), this.count); }'],
  ] as const) {
    it(`is refused in ${what} (there is no _newAmount)`, () => {
      const errs = compileErrors(`
class Pot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  ${body}
}
`);
      expect(errs.join(' | ')).toContain(CONTINUATION_AMOUNT_UNAVAILABLE);
    });
  }

  it('is refused in a private helper', () => {
    const errs = compileErrors(`
class Pot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private amt(): bigint { return continuationAmount(); }
  public bump() { this.count = this.count + this.amt(); }
}
`);
    expect(errs.join(' | ')).toContain(CONTINUATION_AMOUNT_UNAVAILABLE);
  });
});
