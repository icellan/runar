/**
 * N-021 — a `=begin` ... `=end` block in .runar.rb is a comment, on chain.
 *
 * The reference tier lexed a column-0 `=begin` ... `=end` embedded document as
 * live code. For the crafted P2PKH below, the "commented-out" `drain(sig, pk)
 * { assert true }` became the only spend path, the `end` of `=end` closed the
 * class early and the guarded `unlock` was dropped. The TS artifact was 517777
 * (OP_TRUE OP_NIP OP_NIP): anyone-can-spend.
 *
 * The acceptance oracle is the real `@bsv/sdk` Spend engine
 * (`runStatelessSigned`, interpreter check OFF — never TestContract). The
 * attack is a KEYLESS spend: an empty signature plus an attacker-chosen pubkey,
 * tried against EVERY public method the artifact exposes, with the contract
 * locked to alice's pubkey hash. Expected verdicts are derived by hand from the
 * source (hash160(bob) != alice's pkh; an empty sig never verifies).
 *
 * What this proves: whatever the reference tier emits for the backdoor shape,
 * no public method accepts a keyless spend (pre-fix `drain` DID — the recorded
 * failing run); the artifact's only public method is `unlock`; and the control
 * shows the same harness accepts alice's real signature, so the reject is not
 * vacuous.
 * What it does NOT prove: anything about the other six tiers (their suites and
 * the cross-tier conformance test pin their bytes to the same golden).
 */

import { describe, it, expect } from 'vitest';
import { compile } from 'runar-compiler';
import type { RunarArtifact } from 'runar-ir-schema';
import { runStatelessSigned, testKey } from '../oracle/real-crypto-execution.js';
import { hexToBytes } from '../vm/utils.js';

const FILE = 'P2PKH.runar.rb';

const SOURCE = [
  "require 'runar'",
  '',
  'class P2PKH < Runar::SmartContract',
  '  prop :pub_key_hash, Addr',
  '',
  '  def initialize(pub_key_hash)',
  '    super(pub_key_hash)',
  '    @pub_key_hash = pub_key_hash',
  '  end',
  '',
  '=begin',
  '  Old debugging entry point, disabled:',
  '  runar_public sig: Sig, pk: PubKey',
  '  def drain(sig, pk)',
  '    assert true',
  '  end',
  'end',
  '=end',
  '',
  '  runar_public sig: Sig, pub_key: PubKey',
  '  def unlock(sig, pub_key)',
  '    assert hash160(pub_key) == @pub_key_hash',
  '    assert check_sig(sig, pub_key)',
  '  end',
  'end',
  '',
].join('\n');

const constructorArgs = { pubKeyHash: testKey('alice').pubKeyHash };

function publicMethods(): string[] {
  const r = compile(SOURCE, { fileName: FILE });
  expect(r.success, JSON.stringify(r.diagnostics)).toBe(true);
  return (r.artifact as unknown as RunarArtifact).abi.methods.filter((m) => m.isPublic).map((m) => m.name);
}

describe('N-021 — a commented-out .runar.rb backdoor is not spendable', () => {
  it('ATTACK a keyless spend (empty sig, attacker pubkey) is rejected by every public method', () => {
    for (const method of publicMethods()) {
      const v = runStatelessSigned({
        source: SOURCE,
        fileName: FILE,
        method,
        args: [new Uint8Array(0), hexToBytes(testKey('bob').pubKey)],
        constructorArgs,
        checkInterpreter: false,
      });
      expect(v.reachedEngine, `${method}: never reached Spend: ${v.vmError}`).toBe(true);
      expect(v.vmAccepted, `${method} accepted a keyless spend; locking script ${v.lockingHex}`).toBe(false);
    }
  });

  it('the only public method is the guarded unlock', () => {
    expect(publicMethods()).toEqual(['unlock']);
  });

  it("CONTROL alice's real signature and pubkey unlock it (the harness can say yes)", () => {
    const v = runStatelessSigned({
      source: SOURCE,
      fileName: FILE,
      method: 'unlock',
      args: [{ signWith: 'alice' }, hexToBytes(testKey('alice').pubKey)],
      constructorArgs,
      checkInterpreter: false,
    });
    expect(v.vmError).toBeUndefined();
    expect(v.vmAccepted).toBe(true);
  });
});
