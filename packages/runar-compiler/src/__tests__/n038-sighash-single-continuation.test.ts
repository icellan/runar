import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { compile, compileFromANF, loadANFFromJSON } from '../index.js';
import type { ANFBinding } from '../ir/index.js';

/**
 * N-038 (user decision R64) — under a SIGHASH_SINGLE base, BIP-143 commits
 * hashOutputs to hash256(output[inputIndex]) only, so a stateful SINGLE
 * method's auto-injected continuation hashes the method's own output and
 * nothing else: no change segment, and no `_changePKH` / `_changeAmount`
 * parameter in the ANF or the ABI. ALL (and every other base) is unchanged.
 *
 * Proves: the SINGLE method's ABI is exactly [txPreimage] and it stays
 * non-terminal; its ANF never loads a change param or builds a change output;
 * a default-mode method in the same contract keeps both; the emitted IR passes
 * the `--ir` scaffolding check and recompiles to the same bytes; a SINGLE
 * method whose IR still carries the pre-N-038 change segment is refused.
 * Does not prove: on-chain acceptance (runar-sdk n038-sighash-single-change
 * and conformance/sdk-call replay that through @bsv/sdk Spend) or the other
 * six tiers (each tier's own N-038 test compares conformance/sdk-call/expected-{ir.json,script.hex}).
 */

const REPO = join(__dirname, '../../../..');
const SOURCE = readFileSync(join(REPO, 'conformance/sdk-call/SingleCounter.runar.ts'), 'utf8');
const FIXTURE = join(REPO, 'conformance/sdk-call');
const IR_JSON = readFileSync(join(FIXTURE, 'expected-ir.json'), 'utf8');
const GOLDEN_HEX = readFileSync(join(FIXTURE, 'expected-script.hex'), 'utf8').trim();

function compileSingle() {
  const r = compile(SOURCE, { fileName: 'SingleCounter.runar.ts', disableConstantFolding: true });
  expect(r.artifact, r.diagnostics.map((d) => d.message).join('; ')).toBeTruthy();
  return r.artifact!;
}

function walk(bindings: ANFBinding[], visit: (b: ANFBinding) => void): void {
  for (const b of bindings) {
    visit(b);
    const v = b.value as { then?: ANFBinding[]; else?: ANFBinding[]; body?: ANFBinding[] };
    for (const n of [v.then, v.else, v.body]) if (Array.isArray(n)) walk(n, visit);
  }
}

function usesChange(bindings: ANFBinding[]): boolean {
  let hit = false;
  walk(bindings, (b) => {
    const v = b.value as { kind: string; name?: string; func?: string };
    if (v.kind === 'load_param' && (v.name === '_changePKH' || v.name === '_changeAmount')) hit = true;
    if (v.kind === 'call' && v.func === 'buildChangeOutput') hit = true;
  });
  return hit;
}

describe('N-038: a SIGHASH_SINGLE stateful continuation commits only the same-index output', () => {
  it('the SINGLE method declares no change params and stays non-terminal; ALL keeps them', () => {
    const a = compileSingle();
    const bump = a.abi.methods.find((m) => m.name === 'bump')!;
    const reset = a.abi.methods.find((m) => m.name === 'reset')!;
    expect(bump.sigHashType).toBe(0x43);
    expect(bump.params.map((p) => p.name)).toEqual(['txPreimage']);
    expect(bump.isTerminal).toBeUndefined();
    expect(reset.params.map((p) => p.name)).toEqual(['_changePKH', '_changeAmount', '_newAmount', 'txPreimage']);
  });

  it('the SINGLE ANF has no change segment; the ALL ANF does', () => {
    const anf = compileSingle().anf!;
    const bump = anf.methods.find((m) => m.name === 'bump')!;
    const reset = anf.methods.find((m) => m.name === 'reset')!;
    expect(bump.params.map((p) => p.name)).toEqual(['txPreimage']);
    expect(usesChange(bump.body)).toBe(false);
    expect(usesChange(reset.body)).toBe(true);
  });

  it('the fixture IR passes the --ir scaffolding check and recompiles to the golden bytes', () => {
    expect(compileSingle().script).toBe(GOLDEN_HEX);
    expect(compileFromANF(loadANFFromJSON(IR_JSON)).scriptHex).toBe(GOLDEN_HEX);
  });

  it('the --ir check derives the change params from the declared mode', () => {
    // Relabel bump as default ALL|FORKID consistently (ABI field, the
    // check_preimage flag and the prologue's sighash-type constant). The
    // check must then demand the change params a default-mode continuation
    // carries, which the change-free SINGLE body does not declare.
    const ir = JSON.parse(IR_JSON) as {
      methods: Array<{ name: string; sigHashType?: number; body: Array<{ value: Record<string, unknown> }> }>;
    };
    const bump = ir.methods.find((m) => m.name === 'bump')!;
    expect(bump.sigHashType).toBe(0x43);
    delete bump.sigHashType;
    for (const b of bump.body) {
      if (b.value.kind === 'check_preimage') delete b.value.sighashFlag;
      if (b.value.kind === 'load_const' && (b.value.value === 67 || b.value.value === '67')) b.value.value = 65;
    }
    expect(() => compileFromANF(loadANFFromJSON(JSON.stringify(ir)))).toThrow(
      /must declare the auto-injected parameters \(_changePKH: Ripemd160, _changeAmount: bigint, txPreimage: SigHashPreimage\)/,
    );
  });
});
