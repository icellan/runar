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
  it('finds the real OP_RETURN (skips 0x6a inside push data)', () => {
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

    // 106 = 0x6a → NUM2BIN(8): "6a00000000000000"
    // Full script: "51ac" + "6a" + "6a00000000000000"
    // findLastOpReturn stops at the first OP_RETURN (offset 4) and does
    // NOT continue into raw state bytes where 0x6a appears again.
    const stateHex = serializeState(fields, { count: 106n });
    expect(stateHex).toBe('6a00000000000000'); // sanity check
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

describe('serializeState — encoding specifics (NUM2BIN fixed-width)', () => {
  it('encodes bigint 0n as 8 zero bytes', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 0n });
    // NUM2BIN(0, 8) → 8 zero bytes
    expect(hex).toBe('0000000000000000');
  });

  it('encodes bigint 42n as 8-byte LE', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 42n });
    // 42 = 0x2a → LE 8 bytes: 2a 00 00 00 00 00 00 00
    expect(hex).toBe('2a00000000000000');
  });

  it('encodes bigint 1000n as 8-byte LE', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 1000n });
    // 1000 = 0x03E8 → LE 8 bytes: e8 03 00 00 00 00 00 00
    expect(hex).toBe('e803000000000000');
  });

  it('encodes bigint 128n as 8-byte LE (no sign-bit issue in fixed-width)', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: 128n });
    // 128 = 0x80 → LE 8 bytes: 80 00 00 00 00 00 00 00
    // Sign bit is in byte[7] which is 0x00, so positive
    expect(hex).toBe('8000000000000000');
  });

  it('encodes negative bigint -128n with sign bit in MSB of last byte', () => {
    const fields = makeFields({ name: 'v', type: 'bigint', index: 0 });
    const hex = serializeState(fields, { v: -128n });
    // abs(128) = 0x80 → LE: 80 00 00 00 00 00 00 00
    // Negative → set bit 7 of last byte: 80 00 00 00 00 00 00 80
    expect(hex).toBe('8000000000000080');
  });

  it('encodes bool true as raw byte 0x01', () => {
    const fields = makeFields({ name: 'flag', type: 'bool', index: 0 });
    const hex = serializeState(fields, { flag: true });
    expect(hex).toBe('01');
  });

  it('encodes bool false as raw byte 0x00', () => {
    const fields = makeFields({ name: 'flag', type: 'bool', index: 0 });
    const hex = serializeState(fields, { flag: false });
    expect(hex).toBe('00');
  });

  it('encodes PubKey as raw 33 bytes (no push-data prefix)', () => {
    const pubkey = 'ff'.repeat(33);
    const fields = makeFields({ name: 'pk', type: 'PubKey', index: 0 });
    const hex = serializeState(fields, { pk: pubkey });
    expect(hex).toBe(pubkey);
  });

  it('encodes Addr as raw 20 bytes (no push-data prefix)', () => {
    const addr = 'aa'.repeat(20);
    const fields = makeFields({ name: 'a', type: 'Addr', index: 0 });
    const hex = serializeState(fields, { a: addr });
    expect(hex).toBe(addr);
  });
});
