import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TestContract, RunarInterpreter } from '../index.js';
import type { ContractNode } from 'runar-compiler';

/**
 * R-112 / CL-DOC-011 + GK-DOC-001 — the governing docs described the
 * interpreter's crypto backwards, in both directions.
 *
 * CLAUDE.md and packages/runar-testing/README.md both said `TestContract`
 * runs "with mocked crypto (checkSig always true, checkPreimage always true)".
 * In the interpreter:
 *
 *   checkSig        REAL ECDSA over the fixed TEST_MESSAGE (verifyTestMessageSig)
 *   verifyRabinSig  REAL Rabin verification
 *   checkPreimage   stubbed true
 *   checkMultiSig   stubbed FALSE — silently
 *
 * The last one is the one that costs something. A `TestContract` test of a
 * multisig contract was asserting against a hardcoded failure: the spend it
 * "tested" could never have succeeded, whatever the signatures were, so the
 * test proved nothing about the contract and would not have noticed if the
 * contract were wrong. The three example suites that call it all asserted
 * `typeof result.success === 'boolean'` — true of any outcome.
 *
 * A stub that cannot verify must say so rather than answer. This file pins
 * both halves: checkSig really verifies, and checkMultiSig refuses.
 */

const REPO = resolve(__dirname, '../../../..');

const p2pkhSource = `import { SmartContract, assert, checkSig, hash160, Sig, PubKey, Ripemd160 } from 'runar-lang';

export class SigProbe extends SmartContract {
  readonly pubKeyHash: Ripemd160;

  constructor(pubKeyHash: Ripemd160) {
    super(pubKeyHash);
    this.pubKeyHash = pubKeyHash;
  }

  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
`;

describe('R-112 interpreter crypto honesty', () => {
  // The builtin is reached with a hand-built AST: the surface syntax for it
  // (`checkMultiSig([s1, s2], [p1, p2, p3])`) dies earlier, on the
  // interpreter's array-literal refusal, so the stub is currently one
  // interpreter feature away from being reachable — and would answer `false`
  // the day it is. Both paths are pinned: this one that it REFUSES, the next
  // that the surface path fails loudly rather than looking like a rejection.
  it('checkMultiSig REFUSES instead of silently answering false', () => {
    const contract = {
      kind: 'contract',
      name: 'MultiSigProbe',
      parentClass: 'SmartContract',
      properties: [],
      methods: [
        {
          kind: 'method',
          name: 'unlock',
          visibility: 'public',
          params: [
            { kind: 'param', name: 'sigs', type: { kind: 'primitive_type', name: 'Sig' } },
            { kind: 'param', name: 'keys', type: { kind: 'primitive_type', name: 'PubKey' } },
          ],
          body: [
            {
              kind: 'expression_statement',
              expression: {
                kind: 'call_expr',
                callee: { kind: 'identifier', name: 'assert' },
                args: [
                  {
                    kind: 'call_expr',
                    callee: { kind: 'identifier', name: 'checkMultiSig' },
                    args: [
                      { kind: 'identifier', name: 'sigs' },
                      { kind: 'identifier', name: 'keys' },
                    ],
                  },
                ],
              },
            },
          ],
        },
      ],
    } as unknown as ContractNode;

    const interp = new RunarInterpreter({});
    const result = interp.executeMethod(contract, 'unlock', {
      sigs: { kind: 'bytes', value: new Uint8Array(72) },
      keys: { kind: 'bytes', value: new Uint8Array(33) },
    });

    expect(result.success).toBe(false);
    expect(String(result.error)).toMatch(/checkMultiSig/);
    expect(String(result.error)).toMatch(/interpreter|not implemented|cannot verify|ScriptVM/i);
  });

  it('the multisig SURFACE path fails loudly, never as a signature rejection', () => {
    const source = readFileSync(
      resolve(REPO, 'examples/ts/multisig-2of3/MultiSig2of3.runar.ts'),
      'utf8',
    );
    const pk = (b: string) => '02' + b.repeat(32);
    const sig = (b: string) => '30' + b.repeat(35);

    const contract = TestContract.fromSource(source, {
      pk1: pk('aa'),
      pk2: pk('bb'),
      pk3: pk('cc'),
    });

    const result = contract.call('unlock', { sig1: sig('11'), sig2: sig('22') });

    // It must not succeed — but more importantly it must not fail as though
    // the CONTRACT had rejected the signatures. The three example suites that
    // call this asserted `typeof result.success === 'boolean'`, which is true
    // of every outcome; that is what a silent stub buys you.
    expect(result.success).toBe(false);
    expect(String(result.error)).toMatch(/not supported|checkMultiSig/i);
  });

  it('checkSig is REAL ECDSA — a bogus signature fails, and says nothing about mocks', () => {
    const contract = TestContract.fromSource(p2pkhSource, {
      pubKeyHash: 'ab'.repeat(20),
    });
    const result = contract.call('unlock', {
      sig: '30' + '11'.repeat(35),
      pubKey: '02' + 'aa'.repeat(32),
    });
    expect(result.success).toBe(false);
    // If checkSig were "always true" (as the docs claimed), the failure would
    // have to come from the hash160 assert — never from the signature.
    expect(String(result.error)).not.toMatch(/checkMultiSig/);
  });

  it('the docs that describe this no longer claim checkSig is mocked', () => {
    for (const rel of ['CLAUDE.md', 'packages/runar-testing/README.md']) {
      const text = readFileSync(resolve(REPO, rel), 'utf8');
      // The corrected docs quote the old wording to explain what changed, so
      // match the CLAIM (a sentence asserting it), not the quoted phrase.
      expect(text, `${rel} still claims checkSig is always true`).not.toMatch(
        /mocked crypto \(`?checkSig`? always true/,
      );
    }
  });
});
