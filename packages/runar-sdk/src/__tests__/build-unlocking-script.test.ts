import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import type { RunarArtifact } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeArtifact(
  overrides: Partial<RunarArtifact> & Pick<RunarArtifact, 'script' | 'abi'>,
): RunarArtifact {
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
// Method selector encoding
// ---------------------------------------------------------------------------

describe('buildUnlockingScript — method selector', () => {
  it('does NOT append a method selector when contract has a single public method', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'unlock', params: [{ name: 'sig', type: 'Sig' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const sig = 'aa'.repeat(72); // 72-byte DER signature
    const script = contract.buildUnlockingScript('unlock', [sig]);

    // Should be ONLY the push-data-encoded signature, no trailing selector
    // 72 in hex is 0x48, and 72 <= 75, so direct push encoding: length byte + data
    const expected = '48' + sig;
    expect(script).toBe(expected);
  });

  it('appends OP_0 (0x00) as method selector for index 0 with multiple methods', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'release', params: [], isPublic: true },
          { name: 'refund', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const script = contract.buildUnlockingScript('release', []);

    // Method index 0 encodes as encodeScriptNumber(0n) = '00' (OP_0)
    expect(script).toBe('00');
  });

  it('appends OP_1 (0x51) as method selector for index 1 with multiple methods', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'release', params: [], isPublic: true },
          { name: 'refund', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const script = contract.buildUnlockingScript('refund', []);

    // Method index 1 encodes as encodeScriptNumber(1n) = '51' (OP_1)
    expect(script).toBe('51');
  });

  it('correctly indexes past non-public methods (only public methods count)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'release', params: [], isPublic: true },
          { name: '_helper', params: [], isPublic: false },
          { name: 'refund', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    // 'refund' is public method index 1 (skipping the private _helper)
    const script = contract.buildUnlockingScript('refund', []);
    expect(script).toBe('51'); // OP_1
  });

  it('throws for unknown method name', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'release', params: [], isPublic: true },
          { name: 'refund', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    expect(() => contract.buildUnlockingScript('nonexistent', [])).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Argument encoding
// ---------------------------------------------------------------------------

describe('buildUnlockingScript — argument encoding', () => {
  it('encodes bigint 0n as OP_0 (0x00)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'n', type: 'bigint' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const script = contract.buildUnlockingScript('check', [0n]);
    expect(script).toBe('00');
  });

  it('encodes bigint 1n-16n as OP_1 through OP_16 (single-byte opcodes)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'n', type: 'bigint' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);

    // OP_1 = 0x51, OP_2 = 0x52, ..., OP_16 = 0x60
    expect(contract.buildUnlockingScript('check', [1n])).toBe('51');
    expect(contract.buildUnlockingScript('check', [5n])).toBe('55');
    expect(contract.buildUnlockingScript('check', [16n])).toBe('60');
  });

  it('encodes bigint -1n as OP_1NEGATE (0x4f)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'n', type: 'bigint' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    expect(contract.buildUnlockingScript('check', [-1n])).toBe('4f');
  });

  it('encodes bigint 1000n as push-data script number (LE: e803)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'n', type: 'bigint' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    // 1000 = 0x03E8 → little-endian bytes: e8, 03 → push 2 bytes: 02 e8 03
    expect(contract.buildUnlockingScript('check', [1000n])).toBe('02e803');
  });

  it('encodes a negative bigint with the sign bit in the MSB', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'n', type: 'bigint' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    // -42 in Bitcoin Script number encoding:
    // abs(42) = 0x2a → bytes: [0x2a], high bit not set, so set sign bit: 0x2a | 0x80 = 0xaa
    // push 1 byte: 01 aa
    expect(contract.buildUnlockingScript('check', [-42n])).toBe('01aa');
  });

  it('encodes 20-byte hex string with direct push prefix (0x14)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'h', type: 'Addr' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const addr = 'aa'.repeat(20); // 20 bytes
    const script = contract.buildUnlockingScript('check', [addr]);
    // 20 bytes = 0x14 length prefix (direct push, since 20 <= 75)
    expect(script).toBe('14' + addr);
  });

  it('encodes 33-byte hex string with direct push prefix (0x21)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'pk', type: 'PubKey' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const pubkey = 'bb'.repeat(33); // 33 bytes (compressed pubkey)
    const script = contract.buildUnlockingScript('check', [pubkey]);
    // 33 bytes = 0x21 length prefix
    expect(script).toBe('21' + pubkey);
  });

  it('encodes boolean true as OP_1 (0x51)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'flag', type: 'bool' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    expect(contract.buildUnlockingScript('check', [true])).toBe('51');
  });

  it('encodes boolean false as OP_0 (0x00)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'check', params: [{ name: 'flag', type: 'bool' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    expect(contract.buildUnlockingScript('check', [false])).toBe('00');
  });
});

// ---------------------------------------------------------------------------
// Combined: arguments + method selector
// ---------------------------------------------------------------------------

describe('buildUnlockingScript — args with method selector', () => {
  it('pushes args first, then method selector at the end', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'release', params: [{ name: 'sig', type: 'Sig' }], isPublic: true },
          { name: 'refund', params: [{ name: 'sig', type: 'Sig' }], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const sig = 'cc'.repeat(71); // 71-byte signature
    const script = contract.buildUnlockingScript('release', [sig]);

    // sig push: 71 bytes → length prefix 0x47, then method index 0 → OP_0 (0x00)
    const expectedSigPush = '47' + sig;
    expect(script).toBe(expectedSigPush + '00');
  });

  it('encodes multiple args followed by method selector', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          {
            name: 'multisig',
            params: [
              { name: 'sig1', type: 'Sig' },
              { name: 'sig2', type: 'Sig' },
            ],
            isPublic: true,
          },
          { name: 'timeout', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);
    const sig1 = 'aa'.repeat(70);
    const sig2 = 'bb'.repeat(70);
    const script = contract.buildUnlockingScript('multisig', [sig1, sig2]);

    // 70 bytes = 0x46 push prefix
    const push1 = '46' + sig1;
    const push2 = '46' + sig2;
    // method index 0 → OP_0
    expect(script).toBe(push1 + push2 + '00');
  });

  it('handles 3+ public methods with correct index encoding', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [
          { name: 'a', params: [], isPublic: true },
          { name: 'b', params: [], isPublic: true },
          { name: 'c', params: [], isPublic: true },
        ],
      },
    });

    const contract = new RunarContract(artifact, []);

    // Index 0 → OP_0 (0x00)
    expect(contract.buildUnlockingScript('a', [])).toBe('00');
    // Index 1 → OP_1 (0x51)
    expect(contract.buildUnlockingScript('b', [])).toBe('51');
    // Index 2 → OP_2 (0x52)
    expect(contract.buildUnlockingScript('c', [])).toBe('52');
  });
});
