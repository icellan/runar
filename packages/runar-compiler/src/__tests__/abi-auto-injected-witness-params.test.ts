/**
 * The artifact ABI must list the witness params the locking script actually
 * reads.
 *
 * `requireOutputP2PKH` / `extractPrevOutputScript` auto-inject `_serialisedOutputs`
 * and `_prevOutScript_<i>` during ANF lowering (pass 04). The artifact's ABI,
 * however, was built from the AST's `method.params`, which predate that pass —
 * so those params existed in the compiled script and in the ANF, but not in the
 * ABI the SDK reads to decide which witness values a caller must supply.
 *
 * The divergence was 1-vs-5: Go, Rust, Python, Ruby and Zig all list
 * `_serialisedOutputs`; only the TypeScript tier dropped it. Nothing caught it
 * because no conformance golden carries the ABI (`expected-ir.json` holds
 * contractName/methods/properties only) and no sdk-output fixture exercises a
 * contract with an auto-injected witness param at all.
 *
 * The ANF is the authority here — it is byte-identical across all seven tiers,
 * and `conformance/tests/intent-output-p2pkh/expected-ir.json` records
 * `payBond` as taking `['txPreimage', '_serialisedOutputs']`.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { compile } from '../index.js';

const ROOT = join(__dirname, '../../../..');
const SRC = join(ROOT, 'examples/ts/intent-output-p2pkh/IntentOutputP2PKH.runar.ts');

function abiParamNames(result: any, method: string): string[] {
  const m = result.artifact.abi.methods.find((x: any) => x.name === method);
  if (!m) throw new Error(`no ABI method '${method}'`);
  return m.params.map((p: any) => p.name);
}

function anfParamNames(result: any, method: string): string[] {
  const m = result.anf.methods.find((x: any) => x.name === method);
  if (!m) throw new Error(`no ANF method '${method}'`);
  return (m.params ?? []).map((p: any) => p.name);
}

describe('artifact ABI carries the auto-injected witness params', () => {
  const source = readFileSync(SRC, 'utf-8');
  const artifact = compile(source, { fileName: 'IntentOutputP2PKH.runar.ts' });

  it('lists _serialisedOutputs for a method using requireOutputP2PKH', () => {
    expect(abiParamNames(artifact, 'payBond')).toContain('_serialisedOutputs');
  });

  it('matches the ANF param list exactly, which is the cross-tier authority', () => {
    // The ANF is what every tier agrees on byte-for-byte; the ABI claiming a
    // different param list is the defect, in either direction.
    expect(abiParamNames(artifact, 'payBond')).toEqual(anfParamNames(artifact, 'payBond'));
  });

  it('matches the checked-in seven-tier ANF golden', () => {
    const golden = JSON.parse(
      readFileSync(join(ROOT, 'conformance/tests/intent-output-p2pkh/expected-ir.json'), 'utf-8'),
    );
    const g = golden.methods.find((m: any) => m.name === 'payBond');
    expect(abiParamNames(artifact, 'payBond')).toEqual(g.params.map((p: any) => p.name));
  });

  it('appends the witness param AFTER txPreimage', () => {
    const names = abiParamNames(artifact, 'payBond');
    expect(names.indexOf('_serialisedOutputs')).toBeGreaterThan(names.indexOf('txPreimage'));
  });

  it('does not invent witness params on a contract that uses none', () => {
    const plain = `
import { SmartContract, assert } from 'runar-lang';
class Plain extends SmartContract {
  readonly n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public check(x: bigint) { assert(x === this.n); }
}`;
    const a = compile(plain, { fileName: 'Plain.runar.ts' });
    const names = abiParamNames(a, 'check');
    expect(names.some((n) => n === '_serialisedOutputs' || n.startsWith('_prevOutScript_'))).toBe(false);
    expect(names).toEqual(['x']);
  });
});
