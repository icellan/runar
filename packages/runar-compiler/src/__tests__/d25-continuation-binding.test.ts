/**
 * D25 — the contract-level continuation binding (`continuation-binding.ts`):
 * classification, the SINGLE default, the hidden spent-outpoint field, the
 * diagnostics, and the `--ir` check. The executed twin-input theft (RED on
 * origin/main, refused here) lives in
 * `packages/runar-sdk/src/__tests__/d25-twin-input.test.ts`.
 */
import { describe, it, expect } from 'vitest';
import { compile, compileFromANF } from '../index.js';
import type { ANFProgram, ANFBinding } from '../ir/index.js';
import { TWIN_BINDING_FIELD } from '../passes/continuation-binding.js';

const STATEFUL = `import { StatefulSmartContract, assert, checkSig, extractAmount, extractOutputHash, hash256 } from 'runar-lang';
import type { PubKey, Sig, Sha256 } from 'runar-lang';
`;

function counter(incDirective = '', decDirective = ''): string {
  return `${STATEFUL}
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  ${incDirective}
  public increment() { this.count++; }
  ${decDirective}
  public decrement() { assert(this.count > 0n); this.count--; }
}`;
}

const MIXED = `${STATEFUL}
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}`;

function ok(src: string, name: string) {
  const r = compile(src, { fileName: `${name}.runar.ts` });
  if (!r.success) throw new Error(r.diagnostics.map((d) => d.message).join('; '));
  return r;
}

function abiMode(r: ReturnType<typeof compile>, m: string): number | undefined {
  return r.artifact!.abi.methods.find((x) => x.name === m)!.sigHashType;
}

function walk(bs: ANFBinding[], f: (b: ANFBinding) => void): void {
  for (const b of bs) {
    f(b);
    const v = b.value as { then?: ANFBinding[]; else?: ANFBinding[]; body?: ANFBinding[] };
    for (const n of [v.then, v.else, v.body]) if (Array.isArray(n)) walk(n, f);
  }
}

describe('D25 class 1 (all continuation methods mutate-only) -> SIGHASH_SINGLE default', () => {
  it('defaults every continuation method to SINGLE|FORKID and drops the change params', () => {
    const r = ok(counter(), 'Counter');
    expect(abiMode(r, 'increment')).toBe(0x43);
    expect(abiMode(r, 'decrement')).toBe(0x43);
    expect(r.artifact!.stateFields!.map((f) => f.name)).toEqual(['count']);
  });

  it('maps ALL|ANYONECANPAY|FORKID to SINGLE|ANYONECANPAY|FORKID', () => {
    const d = '/** @sighash ALL|ANYONECANPAY|FORKID */';
    const r = ok(counter(d, d), 'Counter');
    expect(abiMode(r, 'increment')).toBe(0xc3);
  });

  it('keeps an explicit SINGLE|ANYONECANPAY|FORKID', () => {
    const d = '/** @sighash SINGLE|ANYONECANPAY|FORKID */';
    expect(abiMode(ok(counter(d), 'Counter'), 'increment')).toBe(0xc3);
  });

  it('refuses an explicit ALL|FORKID sibling (it would reopen the twin)', () => {
    const r = compile(counter('', '/** @sighash ALL|FORKID */'), { fileName: 'Counter.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.some((d) => d.severity === 'error' && d.message.includes("method 'decrement': @sighash ALL|FORKID"))).toBe(true);
  });

  it('a terminal method keeps ALL (it makes no continuation)', () => {
    const src = `${STATEFUL}
class Box extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
  public bump() { this.count++; }
  public close(sig: Sig) { assert(checkSig(sig, this.owner)); }
}`;
    const r = ok(src, 'Box');
    expect(abiMode(r, 'bump')).toBe(0x43);
    expect(abiMode(r, 'close')).toBeUndefined();
  });
});

describe('D25 class 2 (mixed) -> hidden spent-outpoint field', () => {
  it('appends a zero-initialised Sha256 field last, outside the constructor ABI', () => {
    const r = ok(MIXED, 'MixedPot');
    expect(r.artifact!.stateFields!.map((f) => f.name)).toEqual(['count', TWIN_BINDING_FIELD]);
    expect(r.artifact!.abi.constructor.params.map((p) => p.name)).toEqual(['count']);
    const prop = r.anf!.properties.find((p) => p.name === TWIN_BINDING_FIELD)!;
    expect(prop.type).toBe('Sha256');
    expect(prop.initialValue).toBe('00'.repeat(32));
    // Every method keeps ALL: no blending of SINGLE and the field.
    expect(abiMode(r, 'increment')).toBeUndefined();
    expect(abiMode(r, 'bump')).toBeUndefined();
  });

  it('writes sha256(extractOutpoint) in the auto-continuation and appends it to addOutput', () => {
    const r = ok(MIXED, 'MixedPot');
    const inc = r.anf!.methods.find((m) => m.name === 'increment')!;
    const writes: string[] = [];
    walk(inc.body, (b) => { if (b.value.kind === 'update_prop') writes.push(b.value.name); });
    expect(writes).toContain(TWIN_BINDING_FIELD);
    const bump = r.anf!.methods.find((m) => m.name === 'bump')!;
    const outs: ANFBinding[] = [];
    walk(bump.body, (b) => { if (b.value.kind === 'add_output') outs.push(b); });
    expect(outs).toHaveLength(1);
    expect((outs[0]!.value as { stateValues: string[] }).stateValues).toHaveLength(2);
  });

  it('a mutate-only contract that reads extractOutputHash cannot run under SINGLE, so it is bound', () => {
    const src = `${STATEFUL}
class Peek extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public bump(h: Sha256) { assert(extractOutputHash(this.txPreimage) !== h); this.count++; }
}`;
    const r = ok(src, 'Peek');
    expect(abiMode(r, 'bump')).toBeUndefined();
    expect(r.artifact!.stateFields!.map((f) => f.name)).toEqual(['count', TWIN_BINDING_FIELD]);
  });

  it('the field name is reserved', () => {
    const src = `${STATEFUL}
class X extends StatefulSmartContract {
  _spentOutpointHash: bigint;
  constructor(_spentOutpointHash: bigint) { super(_spentOutpointHash); this._spentOutpointHash = _spentOutpointHash; }
  public bump() { this._spentOutpointHash++; }
}`;
    const r = compile(src, { fileName: 'X.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.some((d) => d.message.includes("'_spentOutpointHash' is reserved"))).toBe(true);
  });
});

describe('D25 class 3 (explicit outputs only)', () => {
  const pot = (body: string) => `${STATEFUL}
class Pot extends StatefulSmartContract {
  count: bigint;
  readonly owner: PubKey;
  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }
  public bump(sig: Sig) { ${body} }
}`;

  it('warns on an unsigned addOutput(extractAmount(...)) re-creation (D12 C1)', () => {
    const r = ok(pot('this.addOutput(extractAmount(this.txPreimage), this.count + 1n);'), 'Pot');
    const w = r.diagnostics.filter((d) => d.severity === 'warning' && d.message.includes('twin-input aliasing'));
    expect(w).toHaveLength(1);
    expect(r.artifact!.stateFields!.map((f) => f.name)).toEqual(['count']);
    expect(abiMode(r, 'bump')).toBeUndefined();
  });

  it('a local initialised from extractAmount is followed', () => {
    const r = ok(pot('const v: bigint = extractAmount(this.txPreimage); this.addOutput(v, this.count + 1n);'), 'Pot');
    expect(r.diagnostics.some((d) => d.message.includes('twin-input aliasing'))).toBe(true);
  });

  it('does not warn when the method checks a signature', () => {
    const r = ok(pot('assert(checkSig(sig, this.owner)); this.addOutput(extractAmount(this.txPreimage), this.count + 1n);'), 'Pot');
    expect(r.diagnostics.some((d) => d.message.includes('twin-input aliasing'))).toBe(false);
  });
});

describe('D25 --ir check', () => {
  const anfOf = (src: string, name: string): ANFProgram => structuredClone(ok(src, name).anf!);

  it('accepts the frontend IR of every class', () => {
    expect(() => compileFromANF(anfOf(counter(), 'Counter'))).not.toThrow();
    expect(() => compileFromANF(anfOf(MIXED, 'MixedPot'))).not.toThrow();
  });

  it('refuses a mutate-only program whose continuation commits under ALL', () => {
    const p = anfOf(counter(), 'Counter');
    const m = p.methods.find((x) => x.name === 'decrement')!;
    // Rebuild decrement as the pre-D25 ALL method: no SINGLE label. The
    // scaffold check then derives a change-carrying shape the params lack,
    // or this rule fires first; either way the program is refused.
    delete (m as { sigHashType?: number }).sigHashType;
    expect(() => compileFromANF(p)).toThrow(/IR validation/);
  });

  it('refuses a mixed program without the binding field', () => {
    // The pre-D25 IR: no field, no write, no extra add_output value, no hash chain.
    const plain = anfOf(MIXED, 'MixedPot');
    plain.properties = plain.properties.filter((x) => x.name !== TWIN_BINDING_FIELD);
    for (const m of plain.methods) {
      const drop = new Set<string>();
      walk(m.body, (b) => {
        if (b.value.kind === 'update_prop' && b.value.name === TWIN_BINDING_FIELD) drop.add(b.name);
        if (b.value.kind === 'add_output') {
          const h = b.value.stateValues.pop()!;
          drop.add(h);
        }
      });
      // the hash chain: sha256 <- extractOutpoint <- load_param txPreimage, found by name
      const byName = new Map<string, ANFBinding>();
      walk(m.body, (b) => byName.set(b.name, b));
      for (const n of [...drop]) {
        const v = byName.get(n)!.value;
        const src = v.kind === 'update_prop' ? v.value : n;
        const sha = byName.get(src)!.value as { args: string[] };
        const eo = byName.get(sha.args[0]!)!.value as { args: string[] };
        drop.add(src); drop.add(sha.args[0]!); drop.add(eo.args[0]!);
      }
      m.body = m.body.filter((b) => !drop.has(b.name));
    }
    expect(() => compileFromANF(plain)).toThrow(/not bound to its input/);
  });

  it('refuses an add_output whose last state value is not the spent outpoint hash', () => {
    const p = anfOf(MIXED, 'MixedPot');
    const bump = p.methods.find((m) => m.name === 'bump')!;
    walk(bump.body, (b) => {
      if (b.value.kind === 'add_output') b.value.stateValues[1] = b.value.stateValues[0]!;
    });
    expect(() => compileFromANF(p)).toThrow(/every add_output must carry/);
  });
});
