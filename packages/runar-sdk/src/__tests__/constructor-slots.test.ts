import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a minimal artifact for testing getLockingScript().
 * Only the fields that RunarContract actually reads are populated.
 */
function makeArtifact(overrides: Partial<RunarArtifact> & Pick<RunarArtifact, 'script' | 'abi'>): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'Test',
    asm: '',
    buildTimestamp: '2026-03-02T00:00:00.000Z',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Constructor slot splicing
// ---------------------------------------------------------------------------

describe('getLockingScript — constructor slot splicing', () => {
  it('splices a 20-byte Addr constructor arg at the correct byte offset (P2PKH)', () => {
    // Script: OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG
    //  hex:    76     a9        00   88              ac
    // The OP_0 at byte offset 2 is the placeholder for pubKeyHash.
    const pubKeyHash = '18f5bdad6dac9a0a5044a970edf2897d67a7562d'; // 20 bytes
    const artifact = makeArtifact({
      contractName: 'P2PKH',
      script: '76a90088ac',
      abi: {
        constructor: { params: [{ name: 'pubKeyHash', type: 'Addr' }] },
        methods: [{ name: 'unlock', params: [{ name: 'sig', type: 'Sig' }, { name: 'pubKey', type: 'PubKey' }], isPublic: true }],
      },
      constructorSlots: [{ paramIndex: 0, byteOffset: 2 }],
    });

    const contract = new RunarContract(artifact, [pubKeyHash]);
    const lockingScript = contract.getLockingScript();

    // Expected: OP_DUP OP_HASH160 <push 20 bytes: pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
    // 76 a9 14 <20 bytes> 88 ac
    // 14 = length prefix for 20 bytes
    const expected = '76a914' + pubKeyHash + '88ac';
    expect(lockingScript).toBe(expected);
  });

  it('splices multiple constructor args at correct offsets', () => {
    // Mock script with two OP_0 placeholders at different positions:
    // OP_0 OP_SWAP OP_0 OP_CHECKSIG
    //  00   7c      00   ac
    // byte offsets: 0 and 2
    const pk1 = 'aa'.repeat(33); // 33-byte compressed pubkey
    const pk2 = 'bb'.repeat(33);
    const artifact = makeArtifact({
      contractName: 'TwoKeys',
      script: '007c00ac',
      abi: {
        constructor: {
          params: [
            { name: 'pk1', type: 'PubKey' },
            { name: 'pk2', type: 'PubKey' },
          ],
        },
        methods: [{ name: 'unlock', params: [], isPublic: true }],
      },
      constructorSlots: [
        { paramIndex: 0, byteOffset: 0 },
        { paramIndex: 1, byteOffset: 2 },
      ],
    });

    const contract = new RunarContract(artifact, [pk1, pk2]);
    const lockingScript = contract.getLockingScript();

    // 21 = 33 in hex (length prefix for 33 bytes)
    const encodedPk1 = '21' + pk1;
    const encodedPk2 = '21' + pk2;
    const expected = encodedPk1 + '7c' + encodedPk2 + 'ac';
    expect(lockingScript).toBe(expected);
  });

  it('R84: a ctor arg with no constructorSlots entry is never appended (not spliced, not tacked on)', () => {
    // Previously this fell back to appending the raw arg to the end of the
    // script ("backward compat" for pre-slot-splicing artifacts). That shape
    // — constructorSlots absent, abi.constructor.params non-empty — is
    // byte-identical to what TODAY's compiler emits when every ctor-needed
    // property is eliminated by DCE (no method ever reads it), so the old
    // fallback silently deployed a script that was NOT the compiled
    // template: the appended bytes leave extra items on the stack and the
    // spend fails the consensus clean-stack rule (see
    // n013-dce-eliminated-ctor-args.test.ts, which proves this against the
    // real `@bsv/sdk` Spend oracle). R84: drop the fallback, matching the
    // Java SDK, which never had it — an arg with no slot is simply not
    // spliced anywhere, and the deployed script equals the template.
    const artifact = makeArtifact({
      script: '76a90088ac',
      abi: {
        constructor: { params: [{ name: 'pubKeyHash', type: 'Addr' }] },
        methods: [{ name: 'unlock', params: [], isPublic: true }],
      },
      // No constructorSlots.
    });

    const pubKeyHash = 'ab'.repeat(20);
    const contract = new RunarContract(artifact, [pubKeyHash]);
    const lockingScript = contract.getLockingScript();

    // New behavior (R84): nothing is appended; the deployed script is
    // exactly the compiled template.
    expect(lockingScript).toBe('76a90088ac');
  });

  it('splices a bigint constructor arg correctly', () => {
    // Script: OP_0 OP_NUMEQUAL OP_VERIFY
    //          00   9c          69
    const artifact = makeArtifact({
      script: '009c69',
      abi: {
        constructor: { params: [{ name: 'threshold', type: 'bigint' }] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      constructorSlots: [{ paramIndex: 0, byteOffset: 0 }],
    });

    const contract = new RunarContract(artifact, [1000n]);
    const lockingScript = contract.getLockingScript();

    // 1000 = 0x03E8, as script number (little-endian): e8 03
    // push-data encoding: 02 e8 03  (02 = 2-byte length prefix)
    expect(lockingScript).toBe('02e8039c69');
  });

  it('does not corrupt legitimate OP_0 values outside placeholder positions', () => {
    // Script has a real OP_0 at byte 0 and a placeholder at byte 2.
    // OP_0 OP_ADD OP_0 OP_EQUALVERIFY
    //  00   93     00   88
    // Only the OP_0 at byte 2 should be replaced.
    const artifact = makeArtifact({
      script: '00930088',
      abi: {
        constructor: { params: [{ name: 'x', type: 'bigint' }] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      constructorSlots: [{ paramIndex: 0, byteOffset: 2 }],
    });

    const contract = new RunarContract(artifact, [42n]);
    const lockingScript = contract.getLockingScript();

    // 42 = 0x2a, script number encoding: 01 2a (1-byte length prefix + value)
    // The OP_0 at byte 0 stays untouched
    expect(lockingScript).toBe('0093' + '012a' + '88');
  });

  it('N-081: throws a named error instead of splicing "undefined" when a constructorSlots paramIndex is out of range', () => {
    // The constructor only checks `constructorArgs.length === abi.constructor.params.length`
    // (see contract.ts ~L499) — it never cross-checks that every
    // constructorSlots[].paramIndex actually falls within that range. A
    // malformed or hostile artifact (hand-crafted JSON, or a buggy producer)
    // can declare a slot with a paramIndex past the end of constructorArgs
    // and slip through that check untouched: there is exactly 1 ctor arg
    // (index 0) below, matching the 1 ABI param, but the slot references
    // paramIndex 1.
    //
    // Before the fix, buildCodeScript's `encodeArg(this.constructorArgs[slot.paramIndex])`
    // read `constructorArgs[1]` -> `undefined`, and encodeArg's fallback
    // (`encodePushData(String(value))`) silently spliced the literal bytes
    // of the string "undefined" into the deployed locking script hex
    // instead of refusing. This proves the fix fails closed with a named
    // error instead.
    //
    // What this does NOT prove: it does not cover the two other sites in
    // this file that index `constructorArgs[slot.paramIndex]` without the
    // same guard (`adjustCodeSepOffset`, used by `getSubscriptForSigning` /
    // `computeOpPushTxWithCodeSep`, and `_resolvedCodeSepSlotValues` — the
    // latter is already shielded on this path because `buildCodeScript`
    // runs the now-guarded constructor-slot loop first, but
    // `adjustCodeSepOffset` is independently reachable and still unguarded).
    // It also does not cover the pre-existing `constructorArgs.length !==
    // abi.constructor.params.length` check (contract.ts ~L499), which this
    // test deliberately satisfies so the new guard is what's under test,
    // nor the equivalent code path in the other six SDKs.
    const artifact = makeArtifact({
      script: '009c69',
      abi: {
        constructor: { params: [{ name: 'threshold', type: 'bigint' }] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      constructorSlots: [{ paramIndex: 1, byteOffset: 0 }],
    });

    const contract = new RunarContract(artifact, [1000n]);
    expect(() => contract.getLockingScript()).toThrow(/paramIndex/i);
  });
});
