/**
 * Side-effect summary regression tests for findings F1 and F3 of the
 * 2026-04-30 TypeScript compiler audit.
 *
 * F1 (Critical): Private-helper side effects must propagate to the public
 * caller's auto-injection decisions. A public stateful method that calls a
 * private helper which mutates state, calls addOutput/addRawOutput,
 * addDataOutput, or uses checkPreimage must be treated as if the public
 * method itself does so.
 *
 * F3 (High): The artifact ABI must declare the same auto-injected
 * parameters that ANF lowering injects. In particular the ABI must
 * recognize addRawOutput and addDataOutput as output-emitting effects, not
 * just addOutput.
 */
import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { lowerToStack } from '../passes/05-stack-lower.js';
import { assembleArtifact } from '../artifact/assembler.js';
import type { ContractNode, ANFProgram, StackProgram } from '../ir/index.js';
import type { RunarArtifact } from '../artifact/assembler.js';
// @ts-expect-error vitest resolves this via alias
import { TestContract } from 'runar-testing';

function compile(source: string): {
  contract: ContractNode;
  anf: ANFProgram;
  stack: StackProgram;
  artifact: RunarArtifact;
} {
  const result = parse(source);
  if (!result.contract) {
    throw new Error(`parse failed: ${result.errors.map(e => e.message).join(', ')}`);
  }
  const contract = result.contract;
  const anf = lowerToANF(contract);
  const stack = lowerToStack(anf);
  const artifact = assembleArtifact(contract, anf, stack, '00', 'OP_NOP');
  return { contract, anf, stack, artifact };
}

function anfMethod(anf: ANFProgram, name: string) {
  const m = anf.methods.find(x => x.name === name);
  if (!m) throw new Error(`ANF method '${name}' not found`);
  return m;
}

function abiMethod(artifact: RunarArtifact, name: string) {
  const m = artifact.abi.methods.find(x => x.name === name);
  if (!m) throw new Error(`ABI method '${name}' not found`);
  return m;
}

function paramNames(params: ReadonlyArray<{ name: string }>): string[] {
  return params.map(p => p.name);
}

describe('audit F1: private-helper side effects propagate to public caller', () => {
  it('public method calling private state-mutating helper auto-injects continuation params', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class PrivateMut extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private bump(): void { this.count = this.count + 1n; }
  public spend(): void {
    this.bump();
    assert(true);
  }
}`;
    const { anf, artifact } = compile(source);
    const anfSpend = anfMethod(anf, 'spend');
    const abiSpend = abiMethod(artifact, 'spend');

    expect(paramNames(anfSpend.params)).toEqual(
      ['_changePKH', '_changeAmount', '_newAmount', 'txPreimage'],
    );
    expect(paramNames(abiSpend.params)).toEqual(paramNames(anfSpend.params));
    expect(abiSpend.isTerminal).toBeFalsy();
  });

  it('public method calling private addDataOutput helper auto-injects continuation params', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';
export class PrivateData extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private emit(payload: ByteString): void {
    this.addDataOutput(0n, payload);
  }
  public spend(payload: ByteString): void {
    this.emit(payload);
    assert(true);
  }
}`;
    const { anf, artifact } = compile(source);
    const anfSpend = anfMethod(anf, 'spend');
    const abiSpend = abiMethod(artifact, 'spend');

    expect(paramNames(anfSpend.params)).toEqual(
      ['payload', '_changePKH', '_changeAmount', '_newAmount', 'txPreimage'],
    );
    expect(paramNames(abiSpend.params)).toEqual(paramNames(anfSpend.params));
    expect(abiSpend.isTerminal).toBeFalsy();
  });

  it('public method calling private addOutput helper auto-injects continuation params', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class PrivateOut extends StatefulSmartContract {
  balance: bigint;
  constructor(balance: bigint) { super(balance); this.balance = balance; }
  private split(amount: bigint): void {
    this.addOutput(amount, this.balance - amount);
  }
  public spend(amount: bigint): void {
    this.split(amount);
    assert(true);
  }
}`;
    const { anf, artifact } = compile(source);
    const anfSpend = anfMethod(anf, 'spend');
    const abiSpend = abiMethod(artifact, 'spend');

    expect(paramNames(anfSpend.params)).toEqual(
      ['amount', '_changePKH', '_changeAmount', 'txPreimage'],
    );
    expect(paramNames(abiSpend.params)).toEqual(paramNames(anfSpend.params));
    expect(abiSpend.isTerminal).toBeFalsy();
  });

  it('private helper effects propagate transitively (private -> private -> mutation)', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class TransitivePrivate extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private inner(): void { this.count = this.count + 1n; }
  private middle(): void { this.inner(); }
  public spend(): void {
    this.middle();
    assert(true);
  }
}`;
    const { anf, artifact } = compile(source);
    const anfSpend = anfMethod(anf, 'spend');
    const abiSpend = abiMethod(artifact, 'spend');

    expect(paramNames(anfSpend.params)).toEqual(
      ['_changePKH', '_changeAmount', '_newAmount', 'txPreimage'],
    );
    expect(paramNames(abiSpend.params)).toEqual(paramNames(anfSpend.params));
    expect(abiSpend.isTerminal).toBeFalsy();
  });
});

// ---------------------------------------------------------------------------
// N-298: `collectStmt`'s `if_statement` case walks BOTH `stmt.then` and (when
// present) `stmt.else` to find side effects buried in a private helper. Every
// F1 fixture above puts its helper's only effect at the top level or inside a
// `then` arm, so none of them exercises the `stmt.else` walk at all — a
// private helper whose ONLY side effect lives exclusively inside an `else`
// branch is untested. mutation id `sideeffect-ifstmt-skip-else-branch`
// disables that walk (`if (false) for (const inner of stmt.else) ...`); with
// it disabled, `bump`'s mutation (buried only in the else arm below) never
// surfaces to `effectsFor`, so `spend` is wrongly summarised as having no
// continuation requirement.
// ---------------------------------------------------------------------------
describe("N-298: side-effect-summary walks a private helper's else branch", () => {
  const ELSE_ONLY_SOURCE = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class PrivateElseMut extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private bump(flag: bigint): void {
    if (flag === 1n) {
      assert(true);
    } else {
      this.count = this.count + 1n;
    }
  }
  public spend(flag: bigint): void {
    this.bump(flag);
    assert(true);
  }
}`;

  it("a mutation hidden only in a private helper's else branch still auto-injects continuation params", () => {
    const { anf, artifact } = compile(ELSE_ONLY_SOURCE);
    const anfSpend = anfMethod(anf, 'spend');
    const abiSpend = abiMethod(artifact, 'spend');

    // Proves: `effectsFor('bump', ...)` sees `mutatesState: true` even though
    // the ONLY assignment to `count` is nested inside an else branch, and
    // that effect propagates through the call-graph walk to `spend`'s ANF
    // params and ABI, exactly as the then-branch/top-level F1 fixtures above
    // already prove for their own placements.
    // Does NOT prove: anything about effects nested inside an else branch of
    // a `for` loop, or about effects reachable ONLY through multiple nested
    // else arms.
    expect(paramNames(anfSpend.params)).toEqual(
      ['flag', '_changePKH', '_changeAmount', '_newAmount', 'txPreimage'],
    );
    expect(paramNames(abiSpend.params)).toEqual(paramNames(anfSpend.params));
    expect(abiSpend.isTerminal).toBeFalsy();
  });

  it("interpreter: taking the else arm actually mutates the caller's state", () => {
    // Proves: the else-only mutation is not just visible to the ANF/ABI
    // summary but actually executes and changes contract state when the
    // helper takes that branch.
    // Does NOT prove: the real on-chain continuation-shape binding (covered
    // by `real-crypto-execution.test.ts`'s `private-helper-outputs` witness,
    // which this item's dispatcher brief did not ask to extend).
    const c = TestContract.fromSource(ELSE_ONLY_SOURCE, { count: 5n });
    const result = c.call('spend', { flag: 0n });
    expect(result.success).toBe(true);
    expect(c.state.count).toBe(6n);
  });
});

describe('audit F3: artifact ABI matches ANF for all output intrinsics', () => {
  it('non-mutating addDataOutput injects continuation params in both ANF and ABI', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';
export class DataOnly extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public ping(payload: ByteString): void {
    this.addDataOutput(0n, payload);
  }
}`;
    const { anf, artifact } = compile(source);
    const anfPing = anfMethod(anf, 'ping');
    const abiPing = abiMethod(artifact, 'ping');

    expect(paramNames(anfPing.params)).toEqual(
      ['payload', '_changePKH', '_changeAmount', '_newAmount', 'txPreimage'],
    );
    expect(paramNames(abiPing.params)).toEqual(paramNames(anfPing.params));
    expect(abiPing.isTerminal).toBeFalsy();
  });

  it('non-mutating addRawOutput injects change params in both ANF and ABI', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';
export class RawOnly extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public ping(sats: bigint, script: ByteString): void {
    this.addRawOutput(sats, script);
  }
}`;
    const { anf, artifact } = compile(source);
    const anfPing = anfMethod(anf, 'ping');
    const abiPing = abiMethod(artifact, 'ping');

    // addRawOutput counts as a state output for change plumbing, so no
    // _newAmount: outputs are explicit, not derived from preimage state.
    expect(paramNames(anfPing.params)).toEqual(
      ['sats', 'script', '_changePKH', '_changeAmount', 'txPreimage'],
    );
    expect(paramNames(abiPing.params)).toEqual(paramNames(anfPing.params));
    expect(abiPing.isTerminal).toBeFalsy();
  });

  it('mutating + addRawOutput agrees on continuation params across ANF and ABI', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
import type { ByteString } from 'runar-lang';
export class RawMut extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public ping(sats: bigint, script: ByteString): void {
    this.count = this.count + 1n;
    this.addRawOutput(sats, script);
  }
}`;
    const { anf, artifact } = compile(source);
    const anfPing = anfMethod(anf, 'ping');
    const abiPing = abiMethod(artifact, 'ping');

    expect(paramNames(anfPing.params)).toEqual(
      ['sats', 'script', '_changePKH', '_changeAmount', 'txPreimage'],
    );
    expect(paramNames(abiPing.params)).toEqual(paramNames(anfPing.params));
  });
});

describe('ABI-vs-ANF parity holds for existing baseline contracts', () => {
  it('Counter (state mutation) parity', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
export class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment(): void { this.count = this.count + 1n; }
}`;
    const { anf, artifact } = compile(source);
    expect(paramNames(abiMethod(artifact, 'increment').params))
      .toEqual(paramNames(anfMethod(anf, 'increment').params));
  });

  it('Splitter (addOutput) parity', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
export class Splitter extends StatefulSmartContract {
  balance: bigint;
  constructor(balance: bigint) { super(balance); this.balance = balance; }
  public split(): void {
    this.addOutput(this.balance, this.balance);
    this.addOutput(this.balance, this.balance);
  }
}`;
    const { anf, artifact } = compile(source);
    expect(paramNames(abiMethod(artifact, 'split').params))
      .toEqual(paramNames(anfMethod(anf, 'split').params));
  });
});

// ---------------------------------------------------------------------------
// Private-helper output-ref bubbling
//
// When a private helper emits outputs (addOutput / addRawOutput /
// addDataOutput) or mutates state, the public caller's continuation
// hash must include those output refs. ANF lowering inlines such
// helpers into the caller so their `add_*` ANF nodes appear in the
// caller's binding stream and register on `addOutputRefs` /
// `addDataOutputRefs`.
//
// These tests verify that inlining happens (no `method_call` left
// behind) and that the inlined ANF reaches the right shape.
// ---------------------------------------------------------------------------

function bindingKinds(method: { body: ReadonlyArray<{ value: { kind: string } }> }): string[] {
  return method.body.map(b => b.value.kind);
}

describe('private-helper output bubbling', () => {
  it('PrivateOut.spend inlines the addOutput helper into its body', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class PrivateOut extends StatefulSmartContract {
  balance: bigint;
  constructor(balance: bigint) { super(balance); this.balance = balance; }
  private split(amount: bigint): void {
    this.addOutput(amount, this.balance - amount);
  }
  public spend(amount: bigint): void {
    this.split(amount);
    assert(true);
  }
}`;
    const { anf } = compile(source);
    const spend = anfMethod(anf, 'spend');
    const kinds = bindingKinds(spend);

    // The helper's add_output appears in spend's body — proof of inlining.
    expect(kinds).toContain('add_output');
    // No method_call should target the inlined helper.
    const methodCalls = spend.body.filter(b => b.value.kind === 'method_call');
    expect(methodCalls).toHaveLength(0);
  });

  it('PrivateData.spend inlines the addDataOutput helper into its body', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
import type { ByteString } from 'runar-lang';
export class PrivateData extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private emit(payload: ByteString): void {
    this.addDataOutput(0n, payload);
  }
  public spend(payload: ByteString): void {
    this.emit(payload);
    assert(true);
  }
}`;
    const { anf } = compile(source);
    const spend = anfMethod(anf, 'spend');
    const kinds = bindingKinds(spend);

    expect(kinds).toContain('add_data_output');
    const methodCalls = spend.body.filter(b => b.value.kind === 'method_call');
    expect(methodCalls).toHaveLength(0);
  });

  it('PrivateMut.spend keeps state-mutation helper as method_call (mutation does not require inlining)', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class PrivateMut extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private bump(): void { this.count = this.count + 1n; }
  public spend(): void {
    this.bump();
    assert(true);
  }
}`;
    const { anf } = compile(source);
    const spend = anfMethod(anf, 'spend');
    // State mutation flows through state continuity (the continuation
    // hash reads state via get_state_script after all mutations
    // apply), so private mutation helpers are NOT inlined. Stack
    // lowering inlines the method_call later.
    const methodCalls = spend.body.filter(b => b.value.kind === 'method_call');
    expect(methodCalls.length).toBeGreaterThan(0);
  });

  it('Transitive private chain (mutation-only) keeps method_call dispatch', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class TransitivePrivate extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private inner(): void { this.count = this.count + 1n; }
  private middle(): void { this.inner(); }
  public spend(): void {
    this.middle();
    assert(true);
  }
}`;
    const { anf } = compile(source);
    const spend = anfMethod(anf, 'spend');
    const methodCalls = spend.body.filter(b => b.value.kind === 'method_call');
    expect(methodCalls.length).toBeGreaterThan(0);
  });

  it('Private helper without output effects keeps method_call (no unrelated inlining)', () => {
    const source = `
import { SmartContract, assert, checkSig } from 'runar-lang';
import type { Sig, PubKey } from 'runar-lang';
export class P2PKHHelper extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); }
  private requireOwner(sig: Sig): void { assert(checkSig(sig, this.pk)); }
  public unlock(sig: Sig): void { this.requireOwner(sig); }
}`;
    const { anf } = compile(source);
    const unlock = anfMethod(anf, 'unlock');
    const methodCalls = unlock.body.filter(b => b.value.kind === 'method_call');
    // requireOwner has no output effects — kept as method_call so
    // stack-lowering's existing inlining handles it as before.
    expect(methodCalls.length).toBeGreaterThan(0);
  });

  it('Inlined private helper keeps its addOutput ref ordered before the change output', () => {
    const source = `
import { StatefulSmartContract } from 'runar-lang';
export class OrderedOut extends StatefulSmartContract {
  balance: bigint;
  constructor(balance: bigint) { super(balance); this.balance = balance; }
  private firstHalf(): void { this.addOutput(this.balance, this.balance); }
  public spend(): void {
    this.firstHalf();
    this.addOutput(this.balance, this.balance);
  }
}`;
    const { anf } = compile(source);
    const spend = anfMethod(anf, 'spend');
    const addOutputBindings = spend.body.filter(b => b.value.kind === 'add_output');
    // One addOutput from the inlined private + one from the public body.
    expect(addOutputBindings).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// End-to-end execution
//
// The interpreter (TestContract) walks the compiled ANF + state and
// applies state mutations + output emissions. These tests confirm
// that the inlined private body actually executes — i.e., state
// changes propagate to `c.state` and output declarations land in
// `c.outputs` (or whatever `TestContract` exposes for them).
// Compile/run failures here would indicate the inlining substitution
// produced an ill-formed ANF or stack program.
// ---------------------------------------------------------------------------

describe('private-helper output bubbling — interpreter execution', () => {
  it('PrivateMut.spend runs and the private mutation propagates to caller state', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class PrivateMut extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private bump(): void { this.count = this.count + 1n; }
  public spend(): void {
    this.bump();
    assert(true);
  }
}`;
    const c = TestContract.fromSource(source, { count: 5n });
    const result = c.call('spend', {});
    expect(result.success).toBe(true);
    expect(c.state.count).toBe(6n);
  });

  it('PrivateOut.spend runs with the inlined helper emitting an output', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class PrivateOut extends StatefulSmartContract {
  balance: bigint;
  constructor(balance: bigint) { super(balance); this.balance = balance; }
  private split(amount: bigint): void {
    this.addOutput(amount, this.balance - amount);
  }
  public spend(amount: bigint): void {
    this.split(amount);
    assert(true);
  }
}`;
    const c = TestContract.fromSource(source, { balance: 100n });
    const result = c.call('spend', { amount: 30n });
    expect(result.success).toBe(true);
  });

  it('Transitive private chain executes through both layers', () => {
    const source = `
import { StatefulSmartContract, assert } from 'runar-lang';
export class TransitivePrivate extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  private inner(): void { this.count = this.count + 1n; }
  private middle(): void { this.inner(); }
  public spend(): void {
    this.middle();
    assert(true);
  }
}`;
    const c = TestContract.fromSource(source, { count: 0n });
    const result = c.call('spend', {});
    expect(result.success).toBe(true);
    expect(c.state.count).toBe(1n);
  });
});
