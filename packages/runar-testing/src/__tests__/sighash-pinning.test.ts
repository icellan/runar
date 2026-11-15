/**
 * GAP-302 — sighash-type pinning in the auto-injected stateful covenant.
 *
 * Stateful contracts auto-inject `assert(extractSigHashType(txPreimage) === 0x41)`
 * (SIGHASH_ALL | SIGHASH_FORKID) right after the `checkPreimage` assertion.
 * Without it, a spend could use a permissive sighash flag (ANYONECANPAY /
 * SINGLE / NONE) that zeroes out preimage fields a contract may read
 * (extractAmount / extractHashPrevouts / extractSequence).
 *
 * These tests prove (a) the compiled sighash-type check accepts 0x41 and
 * rejects every other flag, exercised directly through the off-chain ScriptVM,
 * and (b) the check is actually auto-injected into stateful contracts.
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import { ScriptVM } from '../vm/script-vm.js';

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}

function compileHex(source: string, fileName: string, constructorArgs?: Record<string, string>): string {
  const r = compile(source, { fileName, constructorArgs });
  if (!r.success || !r.scriptHex) {
    const errs = r.diagnostics.filter((d) => d.severity === 'error').map((d) => d.message).join('\n');
    throw new Error(`compile failed: ${errs}`);
  }
  return r.scriptHex;
}

describe('GAP-302 sighash-type pinning', () => {
  // A stateless guard exercising exactly the codegen the auto-injection emits:
  // extractSigHashType(p) === 0x41. The preimage body is arbitrary — only the
  // trailing 4-byte sighashType field is read.
  //
  // The preimage is a readonly PROPERTY baked in as a constructor argument:
  // a public method's SigHashPreimage parameter must reach checkPreimage()
  // on every path (GK-GAP-010), which a synthetic preimage cannot pass. The
  // extractor and comparison under test lower the same either way.
  const guardSource = `
import { SmartContract, assert, SigHashPreimage, extractSigHashType } from 'runar-lang';

class SigGuard extends SmartContract {
  readonly p: SigHashPreimage;
  constructor(p: SigHashPreimage) { super(p); this.p = p; }
  public unlock() {
    assert(extractSigHashType(this.p) === 0x41n);
  }
}
`;

  function runGuard(sighashTailLE: string): boolean {
    const preimage = 'ab'.repeat(120) + sighashTailLE; // body || sighashType(4 LE)
    const lock = compileHex(guardSource, 'SigGuard.runar.ts', { p: preimage });
    const unlock = '';
    const vm = new ScriptVM();
    return vm.execute(hexToBytes(unlock), hexToBytes(lock)).success;
  }

  it('accepts SIGHASH_ALL | FORKID (0x41)', () => {
    expect(runGuard('41000000')).toBe(true);
  });

  it('rejects a tampered sighash type (0x42)', () => {
    expect(runGuard('42000000')).toBe(false);
  });

  it('rejects SIGHASH_NONE | FORKID (0x42 is NONE|FORKID; test SINGLE|ANYONECANPAY|FORKID 0xc3)', () => {
    // 0xc3 = SIGHASH_SINGLE(0x03) | SIGHASH_ANYONECANPAY(0x80) | FORKID(0x40)
    expect(runGuard('c3000000')).toBe(false);
  });

  it('rejects ANYONECANPAY | ALL | FORKID (0xc1)', () => {
    expect(runGuard('c1000000')).toBe(false);
  });

  it('rejects a zero sighash type (0x00)', () => {
    expect(runGuard('00000000')).toBe(false);
  });

  // The auto-injection itself: every stateful method must carry the
  // sighash-type pin, regardless of whether it declares outputs.
  it('auto-injects the sighash-type pin into stateful methods', () => {
    const counter = `
import { StatefulSmartContract, assert } from 'runar-lang';

class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment() { this.count++; }
}
`;
    const r = compile(counter, { fileName: 'Counter.runar.ts', disableConstantFolding: true });
    expect(r.success).toBe(true);
    // The ANF for the public method must contain a call to extractSigHashType.
    const blob = JSON.stringify(r.anf, (_k, v) => (typeof v === 'bigint' ? `${v}` : v));
    expect(blob).toContain('extractSigHashType');
  });
});
