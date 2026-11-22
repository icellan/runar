/**
 * D25: `lowerToANF` is a public entry point. A caller that assembles its own
 * pipeline (parse -> validate -> typecheck -> lowerToANF) and never runs
 * `injectContinuationBinding` would otherwise lower a mixed ("bind") contract
 * with no `_spentOutpointHash`: its continuations would not be bound to the
 * spent outpoint, which is the twin-input theft D25 closes.
 */
import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';
import { validate } from '../passes/02-validate.js';
import { typecheck } from '../passes/03-typecheck.js';
import { lowerToANF } from '../passes/04-anf-lower.js';
import { injectContinuationBinding, TWIN_BINDING_FIELD } from '../passes/continuation-binding.js';
import type { ContractNode } from '../ir/index.js';

const MIXED = `import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';
class MixedPot extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }
}`;

function frontend(): ContractNode {
  const pr = parse(MIXED, 'MixedPot.runar.ts');
  if (!pr.contract || pr.errors.length > 0) throw new Error(`parse: ${JSON.stringify(pr.errors)}`);
  const v = validate(pr.contract);
  if (v.errors.length > 0) throw new Error(`validate: ${JSON.stringify(v.errors)}`);
  const tc = typecheck(pr.contract);
  if (tc.errors.length > 0) throw new Error(`typecheck: ${JSON.stringify(tc.errors)}`);
  return pr.contract;
}

describe('D25: lowerToANF injects the twin-input binding', () => {
  it('a caller that skipped injection still gets _spentOutpointHash as the last property', () => {
    const props = lowerToANF(frontend()).properties;
    expect(props[props.length - 1]?.name).toBe(TWIN_BINDING_FIELD);
  });

  it('a caller that already injected gets the field exactly once', () => {
    const props = lowerToANF(injectContinuationBinding(frontend())).properties;
    expect(props.filter((p) => p.name === TWIN_BINDING_FIELD)).toHaveLength(1);
  });
});
