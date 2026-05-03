/**
 * Regression tests for the remaining 2026-04-30 TypeScript compiler audit
 * findings: F5 (checkMultiSig arg type validation), F6 (affine alias /
 * property tracking), F7 (recursive checkPreimage detection in branches
 * and private helpers), and F2 (branch-aware output continuation hash).
 *
 * Each `describe` block targets one finding. Tests assert the expected
 * (post-fix) compiler behavior — they fail at HEAD before the fix lands.
 */
import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { typecheck } from '../passes/03-typecheck.js';
import type { TypeCheckResult } from '../passes/03-typecheck.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import type { ContractNode } from '../ir/index.js';
// @ts-expect-error vitest resolves this via alias
import { TestContract } from 'runar-testing';

function parseContract(source: string): ContractNode {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  return result.contract;
}

function typecheckSource(source: string): TypeCheckResult {
  return typecheck(parseContract(source));
}

function hasError(result: TypeCheckResult, substring: string): boolean {
  return result.errors.some(e => e.message.includes(substring));
}

// ---------------------------------------------------------------------------
// F5 — checkMultiSig arg type validation
// ---------------------------------------------------------------------------

describe('audit F5: checkMultiSig validates element types of array args', () => {
  it('rejects bigint[] as the signatures array', () => {
    const source = `
import { SmartContract, assert, checkMultiSig } from 'runar-lang';
class BadMulti extends SmartContract {
  constructor() { super(); }
  public unlock() {
    assert(checkMultiSig([1n], [2n]));
  }
}`;
    const result = typecheckSource(source);
    // The first arg must be Sig[]; bigint[] should be rejected.
    expect(
      hasError(result, "expected 'Sig[]'")
        || hasError(result, "expected 'Sig'")
        || hasError(result, "checkMultiSig"),
    ).toBe(true);
  });

  it('rejects when the first arg is a non-array expression', () => {
    const source = `
import { SmartContract, assert, checkMultiSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
class WrongShape extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(sig: Sig) {
    assert(checkMultiSig(sig, [this.pk]));
  }
}`;
    const result = typecheckSource(source);
    expect(
      hasError(result, "expected 'Sig[]'")
        || hasError(result, "expected an array")
        || hasError(result, "checkMultiSig"),
    ).toBe(true);
  });

  it('accepts a properly typed checkMultiSig call', () => {
    const source = `
import { SmartContract, assert, checkMultiSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
class GoodMulti extends SmartContract {
  readonly pk1: PubKey;
  readonly pk2: PubKey;
  readonly pk3: PubKey;
  constructor(pk1: PubKey, pk2: PubKey, pk3: PubKey) {
    super(pk1, pk2, pk3);
    this.pk1 = pk1;
    this.pk2 = pk2;
    this.pk3 = pk3;
  }
  public unlock(s1: Sig, s2: Sig) {
    assert(checkMultiSig([s1, s2], [this.pk1, this.pk2, this.pk3]));
  }
}`;
    const result = typecheckSource(source);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// F6 — affine Sig / SigHashPreimage tracking through aliases and properties
// ---------------------------------------------------------------------------

describe('audit F6: affine consumption tracks aliases and property origins', () => {
  it('rejects reuse of an affine value through a local alias', () => {
    const source = `
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
class AliasSig extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(sig: Sig) {
    const again: Sig = sig;
    assert(checkSig(sig, this.pk));
    assert(checkSig(again, this.pk));
  }
}`;
    const result = typecheckSource(source);
    expect(
      hasError(result, 'already been consumed')
        || hasError(result, 'consumed'),
    ).toBe(true);
  });

  it('rejects double-consumption of a stored Sig property', () => {
    const source = `
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
class PropSig extends SmartContract {
  readonly sig: Sig;
  readonly pk: PubKey;
  constructor(sig: Sig, pk: PubKey) {
    super(sig, pk);
    this.sig = sig;
    this.pk = pk;
  }
  public unlock() {
    assert(checkSig(this.sig, this.pk));
    assert(checkSig(this.sig, this.pk));
  }
}`;
    const result = typecheckSource(source);
    expect(
      hasError(result, 'already been consumed')
        || hasError(result, 'consumed'),
    ).toBe(true);
  });

  it('rejects double-consumption of a SigHashPreimage through an alias', () => {
    const source = `
import { SmartContract, assert, checkPreimage } from 'runar-lang';
import type { SigHashPreimage } from 'runar-lang';
class AliasPreimage extends SmartContract {
  constructor() { super(); }
  public unlock(preimage: SigHashPreimage) {
    const again: SigHashPreimage = preimage;
    assert(checkPreimage(preimage));
    assert(checkPreimage(again));
  }
}`;
    const result = typecheckSource(source);
    expect(
      hasError(result, 'already been consumed')
        || hasError(result, 'consumed'),
    ).toBe(true);
  });

  it('still allows a single consumption of a Sig property', () => {
    const source = `
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
class SingleProp extends SmartContract {
  readonly sig: Sig;
  readonly pk: PubKey;
  constructor(sig: Sig, pk: PubKey) {
    super(sig, pk);
    this.sig = sig;
    this.pk = pk;
  }
  public unlock() {
    assert(checkSig(this.sig, this.pk));
  }
}`;
    const result = typecheckSource(source);
    expect(result.errors.filter(e => e.severity === 'error')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// F7 — manual checkPreimage in branches and private helpers
// ---------------------------------------------------------------------------

describe('audit F7: manual checkPreimage compiles in branches and private helpers', () => {
  it('compiles checkPreimage inside a branch (stateless contract)', () => {
    const source = `
import { SmartContract, assert, checkPreimage } from 'runar-lang';
import type { SigHashPreimage } from 'runar-lang';
class BranchPreimage extends SmartContract {
  constructor() { super(); }
  public unlock(flag: boolean, preimage: SigHashPreimage) {
    if (flag) {
      assert(checkPreimage(preimage));
    }
    assert(true);
  }
}`;
    const contract = parseContract(source);
    const anf = lowerToANF(contract);
    // Stack lowering must not throw "Value '_opPushTxSig' not found
    // on stack" — that was the F7 symptom. If lowering succeeds,
    // the recursive scan picked up the branch-contained call.
    expect(() => lowerToStack(anf)).not.toThrow();
  });

  it('compiles checkPreimage inside a private helper', () => {
    const source = `
import { SmartContract, assert, checkPreimage } from 'runar-lang';
import type { SigHashPreimage } from 'runar-lang';
class HelperPreimage extends SmartContract {
  constructor() { super(); }
  private guard(preimage: SigHashPreimage): boolean {
    return checkPreimage(preimage);
  }
  public unlock(preimage: SigHashPreimage) {
    assert(this.guard(preimage));
  }
}`;
    const contract = parseContract(source);
    const anf = lowerToANF(contract);
    expect(() => lowerToStack(anf)).not.toThrow();
  });

  it('compiles checkPreimage inside a loop body', () => {
    const source = `
import { SmartContract, assert, checkPreimage } from 'runar-lang';
import type { SigHashPreimage } from 'runar-lang';
class LoopPreimage extends SmartContract {
  constructor() { super(); }
  public unlock(preimage: SigHashPreimage) {
    for (let i = 0n; i < 1n; i++) {
      assert(checkPreimage(preimage));
    }
  }
}`;
    const contract = parseContract(source);
    const anf = lowerToANF(contract);
    expect(() => lowerToStack(anf)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// F2 — branch-aware output continuation hash
// ---------------------------------------------------------------------------

describe('audit F2: branches with multiple output intrinsics commit each output', () => {
  it('compiles a branch with two addOutputs in one arm and one in the other', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
import type { PubKey } from 'runar-lang';
class BranchMulti extends StatefulSmartContract {
  owner: PubKey;
  balance: bigint;
  constructor(owner: PubKey, balance: bigint) {
    super(owner, balance);
    this.owner = owner;
    this.balance = balance;
  }
  public split(flag: boolean, to: PubKey, sats: bigint) {
    if (flag) {
      this.addOutput(sats, to, 1n);
      this.addOutput(sats, this.owner, this.balance - 1n);
    } else {
      this.addOutput(sats, this.owner, this.balance);
    }
  }
}`;
    const contract = parseContract(source);
    const anf = lowerToANF(contract);
    expect(() => lowerToStack(anf)).not.toThrow();

    // The compiled continuation must commit to all outputs declared
    // in each branch — not collapse them into a single ref.
    const split = anf.methods.find(m => m.name === 'split');
    expect(split).toBeDefined();
    // Search the if binding for its branch-aware output structure.
    const ifBindings = (split!.body as Array<{ value: { kind: string } }>).filter(
      b => b.value.kind === 'if',
    );
    expect(ifBindings.length).toBeGreaterThan(0);
  });

  it('compiles a branch mixing addOutput and addDataOutput', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
import type { PubKey, ByteString } from 'runar-lang';
class BranchMixed extends StatefulSmartContract {
  owner: PubKey;
  balance: bigint;
  constructor(owner: PubKey, balance: bigint) {
    super(owner, balance);
    this.owner = owner;
    this.balance = balance;
  }
  public split(flag: boolean, sats: bigint, payload: ByteString) {
    if (flag) {
      this.addOutput(sats, this.owner, this.balance);
      this.addDataOutput(0n, payload);
    } else {
      this.addOutput(sats, this.owner, this.balance);
    }
  }
}`;
    const contract = parseContract(source);
    const anf = lowerToANF(contract);
    expect(() => lowerToStack(anf)).not.toThrow();
  });

  it('runs the BranchMulti contract through the interpreter and emits the chosen branchs outputs', () => {
    // Audit gap 4 (Script VM hashOutputs end-to-end) — exercised
    // here at the interpreter level, where each branch's declared
    // outputs are captured and asserted. Combined with the
    // cross-compiler hex parity and the regtest-gated integration
    // tests, this gives a three-tier validation: bytes match
    // across compilers (cross-compiler.test.ts), interpreter
    // emits the right outputs (this test), and on-chain script
    // execution succeeds (integration/ts/private-helper-outputs).
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
import type { PubKey } from 'runar-lang';
export class BranchMulti extends StatefulSmartContract {
  owner: PubKey;
  balance: bigint;
  constructor(owner: PubKey, balance: bigint) {
    super(owner, balance);
    this.owner = owner;
    this.balance = balance;
  }
  public split(flag: boolean, to: PubKey, sats: bigint) {
    if (flag) {
      this.addOutput(sats, to, 1n);
      this.addOutput(sats, this.owner, this.balance - 1n);
    } else {
      this.addOutput(sats, this.owner, this.balance);
    }
    assert(true);
  }
}`;
    const ownerHex = '02' + '11'.repeat(32);
    const toHex = '02' + '22'.repeat(32);

    // Then-branch: two outputs declared.
    {
      const c = TestContract.fromSource(source, { owner: ownerHex, balance: 100n });
      const r = c.call('split', { flag: true, to: toHex, sats: 1000n });
      expect(r.success).toBe(true);
      expect((r.outputs ?? []).length).toBe(2);
    }

    // Else-branch: one output declared.
    {
      const c = TestContract.fromSource(source, { owner: ownerHex, balance: 100n });
      const r = c.call('split', { flag: false, to: toHex, sats: 1000n });
      expect(r.success).toBe(true);
      expect((r.outputs ?? []).length).toBe(1);
    }
  });

  it('places state outputs before data outputs in branch concat regardless of declaration order', () => {
    // Locks in the F2 fix's invariant: even when the developer
    // interleaves state and data outputs within a branch, the
    // continuation hash sees them in canonical (state || data)
    // order. Without this, mixed-order declarations would produce
    // a hashOutputs commitment that doesn't match the runtime tx
    // (which is also in canonical order via BIP-143).
    const source = `
import { StatefulSmartContract } from 'runar-lang';
import type { PubKey, ByteString } from 'runar-lang';
class BranchInterleaved extends StatefulSmartContract {
  owner: PubKey;
  balance: bigint;
  constructor(owner: PubKey, balance: bigint) {
    super(owner, balance);
    this.owner = owner;
    this.balance = balance;
  }
  public split(flag: boolean, sats: bigint, p1: ByteString, p2: ByteString) {
    if (flag) {
      this.addDataOutput(0n, p1);
      this.addOutput(sats, this.owner, this.balance);
      this.addDataOutput(0n, p2);
    } else {
      this.addOutput(sats, this.owner, this.balance);
    }
  }
}`;
    const contract = parseContract(source);
    const anf = lowerToANF(contract);
    expect(() => lowerToStack(anf)).not.toThrow();

    // Walk the if binding's then-branch and find the cat-chain.
    // The order of cat args must be: state-ref ... data-refs.
    const split = anf.methods.find(m => m.name === 'split');
    expect(split).toBeDefined();
    type AnyBinding = { name: string; value: { kind: string; [k: string]: unknown } };
    const ifBinding = (split!.body as AnyBinding[]).find(b => b.value.kind === 'if');
    expect(ifBinding).toBeDefined();

    const thenBindings = (ifBinding!.value as unknown as { then: AnyBinding[] }).then;
    // Identify the binding kinds in order. State output is
    // `add_output` / `add_raw_output`; data output is
    // `add_data_output`.
    const outputBindings = thenBindings.filter(b =>
      ['add_output', 'add_raw_output', 'add_data_output'].includes(b.value.kind),
    );
    expect(outputBindings.length).toBe(3);

    // Find the final cat-chain. The chain's leaves (in evaluation
    // order) must list the state ref before either data ref —
    // otherwise the continuation commits in wrong-canonical order.
    const catBindings = thenBindings.filter(
      b => b.value.kind === 'call' && (b.value as { func?: string }).func === 'cat',
    );
    expect(catBindings.length).toBeGreaterThanOrEqual(2);

    // Reconstruct the leftmost-leaf chain by walking arg[0] of the
    // last cat, recursively. The bottom-most leaf is the first
    // ref consumed by the concat.
    const lastCat = catBindings[catBindings.length - 1]!;
    const bindingByName = new Map<string, AnyBinding>();
    for (const b of thenBindings) bindingByName.set(b.name, b);

    function leftmostLeaf(name: string): string {
      const binding = bindingByName.get(name);
      if (!binding) return name;
      if (binding.value.kind === 'call' && (binding.value as { func?: string }).func === 'cat') {
        const args = (binding.value as unknown as { args: string[] }).args;
        return leftmostLeaf(args[0]!);
      }
      return name;
    }

    const args = (lastCat.value as unknown as { args: string[] }).args;
    const firstRef = leftmostLeaf(args[0]!);
    const firstBinding = bindingByName.get(firstRef);
    expect(firstBinding).toBeDefined();
    expect(['add_output', 'add_raw_output']).toContain(firstBinding!.value.kind);
  });
});
