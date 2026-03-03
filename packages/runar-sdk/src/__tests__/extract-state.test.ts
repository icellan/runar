import { describe, it, expect } from 'vitest';
import { extractStateFromScript, serializeState, findLastOpReturn } from '../state.js';
import type { RunarArtifact, StateField } from 'runar-ir-schema';

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

function makeFields(
  ...defs: { name: string; type: string; index: number }[]
): StateField[] {
  return defs.map((d) => ({ name: d.name, type: d.type, index: d.index }));
}

// ---------------------------------------------------------------------------
// extractStateFromScript — null cases
// ---------------------------------------------------------------------------

describe('extractStateFromScript — returns null when appropriate', () => {
  it('returns null when artifact has no stateFields', () => {
    const artifact = makeArtifact({
      script: '76a914' + '00'.repeat(20) + '88ac',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'unlock', params: [], isPublic: true }],
      },
      // No stateFields
    });

    const result = extractStateFromScript(artifact, '76a914' + '00'.repeat(20) + '88ac');
    expect(result).toBeNull();
  });

  it('returns null when stateFields is an empty array', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'unlock', params: [], isPublic: true }],
      },
      stateFields: [],
    });

    const result = extractStateFromScript(artifact, '51');
    expect(result).toBeNull();
  });

  it('returns null when script contains no OP_RETURN (0x6a)', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: makeFields({ name: 'count', type: 'bigint', index: 0 }),
    });

    // Use a script that truly has no OP_RETURN opcode
    expect(extractStateFromScript(artifact, '5193885187')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// extractStateFromScript — finds the LAST OP_RETURN
// ---------------------------------------------------------------------------

describe('extractStateFromScript — OP_RETURN location', () => {
  it('finds the last 6a in the script (not the first)', () => {
    const fields = makeFields({ name: 'count', type: 'bigint', index: 0 });
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    // Construct a script where '6a' appears twice:
    // first as part of push data, then as the real OP_RETURN separator.
    // Code section with embedded 0x6a byte, then OP_RETURN, then state.
    // Use '016a' (push 1 byte: 0x6a) as embedded false-positive, then '6a' as separator.
    const codeWithEmbedded6a = '016a93'; // PUSH(0x6a) OP_ADD
    const stateHex = serializeState(fields, { count: 42n });
    const fullScript = codeWithEmbedded6a + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.count).toBe(42n);
  });

  it('extracts state from everything after the last 6a', () => {
    const fields = makeFields(
      { name: 'a', type: 'bigint', index: 0 },
      { name: 'b', type: 'bigint', index: 1 },
    );
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { a: 100n, b: 200n });
    const fullScript = '76a988' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.a).toBe(100n);
    expect(result!.b).toBe(200n);
  });
});

// ---------------------------------------------------------------------------
// extractStateFromScript + serializeState roundtrip
// ---------------------------------------------------------------------------

describe('extractStateFromScript + serializeState roundtrip', () => {
  it('roundtrips a single bigint field through serialize → extract', () => {
    const fields = makeFields({ name: 'count', type: 'bigint', index: 0 });
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { count: 999n });
    const fullScript = 'aabbcc' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.count).toBe(999n);
  });

  it('roundtrips zero bigint', () => {
    const fields = makeFields({ name: 'count', type: 'bigint', index: 0 });
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { count: 0n });
    const fullScript = 'ac' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.count).toBe(0n);
  });

  it('roundtrips a negative bigint', () => {
    const fields = makeFields({ name: 'balance', type: 'bigint', index: 0 });
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { balance: -500n });
    const fullScript = '51' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.balance).toBe(-500n);
  });

  it('roundtrips boolean fields', () => {
    const fields = makeFields(
      { name: 'active', type: 'bool', index: 0 },
      { name: 'paused', type: 'bool', index: 1 },
    );
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { active: true, paused: false });
    const fullScript = 'ac' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.active).toBe(true);
    expect(result!.paused).toBe(false);
  });

  it('roundtrips PubKey field (33-byte hex string)', () => {
    const pubkey = 'cc'.repeat(33);
    const fields = makeFields({ name: 'owner', type: 'PubKey', index: 0 });
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { owner: pubkey });
    const fullScript = '51' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.owner).toBe(pubkey);
  });

  it('roundtrips Addr field (20-byte hex string)', () => {
    const addr = 'dd'.repeat(20);
    const fields = makeFields({ name: 'recipient', type: 'Addr', index: 0 });
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { recipient: addr });
    const fullScript = '51' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.recipient).toBe(addr);
  });

  it('roundtrips Sha256 field (32-byte hex string)', () => {
    const hash = 'ee'.repeat(32);
    const fields = makeFields({ name: 'commitment', type: 'Sha256', index: 0 });
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { commitment: hash });
    const fullScript = '88' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.commitment).toBe(hash);
  });
});

// ---------------------------------------------------------------------------
// extractStateFromScript — field ordering
// ---------------------------------------------------------------------------

describe('extractStateFromScript — field ordering', () => {
  it('deserializes fields by index order regardless of declaration order', () => {
    // Declare fields out of order (index 1 before index 0)
    const fields = makeFields(
      { name: 'b', type: 'bigint', index: 1 },
      { name: 'a', type: 'bigint', index: 0 },
    );
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    // Serialize with the same fields (they get sorted by index internally)
    const stateHex = serializeState(fields, { a: 10n, b: 20n });
    const fullScript = 'ac' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.a).toBe(10n);
    expect(result!.b).toBe(20n);
  });

  it('handles mixed types in correct index order', () => {
    const fields = makeFields(
      { name: 'count', type: 'bigint', index: 0 },
      { name: 'owner', type: 'PubKey', index: 1 },
      { name: 'active', type: 'bool', index: 2 },
    );
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const pubkey = 'ab'.repeat(33);
    const stateHex = serializeState(fields, { count: 7n, owner: pubkey, active: true });
    const fullScript = '51' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.count).toBe(7n);
    expect(result!.owner).toBe(pubkey);
    expect(result!.active).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// extractStateFromScript — 0x6a in state data (regression test)
// ---------------------------------------------------------------------------

describe('extractStateFromScript — 0x6a inside state data', () => {
  it('correctly extracts state when bigint value is 106 (0x6a)', () => {
    const fields = makeFields({ name: 'count', type: 'bigint', index: 0 });
    const artifact = makeArtifact({
      script: '51ac',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    // 106 = 0x6a → state encoding: push 1 byte 0x6a → "016a"
    // Full script: "51ac" + "6a" + "016a"
    // Naive lastIndexOf("6a") would find the last "6a" inside the state data.
    const stateHex = serializeState(fields, { count: 106n });
    expect(stateHex).toBe('016a'); // sanity check
    const fullScript = '51ac' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.count).toBe(106n);
  });

  it('correctly extracts state when PubKey ends with 0x6a', () => {
    const pubkey = 'ab'.repeat(32) + '6a'; // 33 bytes, last byte is 0x6a
    const fields = makeFields(
      { name: 'count', type: 'bigint', index: 0 },
      { name: 'owner', type: 'PubKey', index: 1 },
    );
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { count: 42n, owner: pubkey });
    const fullScript = '51' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.count).toBe(42n);
    expect(result!.owner).toBe(pubkey);
  });

  it('correctly extracts state when Addr ends with 0x6a', () => {
    const addr = 'ff'.repeat(19) + '6a'; // 20 bytes, last byte is 0x6a
    const fields = makeFields({ name: 'recipient', type: 'Addr', index: 0 });
    const artifact = makeArtifact({
      script: '76a988ac',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      stateFields: fields,
    });

    const stateHex = serializeState(fields, { recipient: addr });
    const fullScript = '76a988ac' + '6a' + stateHex;

    const result = extractStateFromScript(artifact, fullScript);
    expect(result).not.toBeNull();
    expect(result!.recipient).toBe(addr);
  });
});

// ---------------------------------------------------------------------------
// findLastOpReturn — opcode-aware walking
// ---------------------------------------------------------------------------

describe('findLastOpReturn', () => {
  it('finds OP_RETURN in simple script', () => {
    // OP_1 OP_RETURN push(1 byte 0x2a)
    expect(findLastOpReturn('516a012a')).toBe(2);
  });

  it('skips 0x6a inside push data', () => {
    // push(1 byte: 0x6a) OP_ADD OP_RETURN push(1 byte: 0x2a)
    // 01 6a 93 6a 01 2a
    expect(findLastOpReturn('016a936a012a')).toBe(6);
  });

  it('returns -1 when no OP_RETURN exists', () => {
    expect(findLastOpReturn('5193885187')).toBe(-1);
  });

  it('skips 0x6a inside OP_PUSHDATA1', () => {
    // OP_PUSHDATA1 len=3 data=[0x6a, 0x6a, 0x6a] OP_RETURN
    expect(findLastOpReturn('4c036a6a6a6a')).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// serializeState — encoding verification
// ---------------------------------------------------------------------------

describe('serializeState — encoding specifics', () => {
  it('encodes bigint 0n as OP_0 (0x00)', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 0n });
    // State encoding: encodeScriptInt(0n) returns '00' (OP_0)
    expect(hex).toBe('00');
  });

  it('encodes bigint 42n as 0x01 0x2a (push 1 byte: 42)', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 42n });
    // 42 = 0x2a, high bit not set, no sign byte needed
    // push 1 byte: 01 2a
    expect(hex).toBe('012a');
  });

  it('encodes bigint 1000n as 0x02 0xe8 0x03 (push 2 bytes LE)', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 1000n });
    // 1000 = 0x03E8 → LE bytes: e8, 03 → push 2 bytes: 02 e8 03
    expect(hex).toBe('02e803');
  });

  it('encodes bigint 128n with an extra zero byte to prevent sign-bit ambiguity', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 128n });
    // 128 = 0x80 → high bit set → must add 0x00 sign byte
    // bytes: [0x80, 0x00] → push 2 bytes: 02 80 00
    expect(hex).toBe('028000');
  });

  it('encodes negative bigint -128n with sign bit in MSB', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: -128n });
    // abs(128) = 0x80 → high bit set → must add sign byte 0x80
    // bytes: [0x80, 0x80] → push 2 bytes: 02 80 80
    expect(hex).toBe('028080');
  });

  it('encodes bool true as OP_1 (0x51)', () => {
    const fields = makeFields({ name: 'flag', type: 'bool', index: 0 });
    const hex = serializeState(fields, { flag: true });
    expect(hex).toBe('51');
  });

  it('encodes bool false as OP_0 (0x00)', () => {
    const fields = makeFields({ name: 'flag', type: 'bool', index: 0 });
    const hex = serializeState(fields, { flag: false });
    expect(hex).toBe('00');
  });

  it('encodes PubKey as push-data with length prefix 0x21 (33 bytes)', () => {
    const pubkey = 'ff'.repeat(33);
    const fields = makeFields({ name: 'pk', type: 'PubKey', index: 0 });
    const hex = serializeState(fields, { pk: pubkey });
    // 33 = 0x21, direct push (33 <= 75)
    expect(hex).toBe('21' + pubkey);
  });

  it('encodes Addr as push-data with length prefix 0x14 (20 bytes)', () => {
    const addr = 'aa'.repeat(20);
    const fields = makeFields({ name: 'a', type: 'Addr', index: 0 });
    const hex = serializeState(fields, { a: addr });
    // 20 = 0x14
    expect(hex).toBe('14' + addr);
  });
});
