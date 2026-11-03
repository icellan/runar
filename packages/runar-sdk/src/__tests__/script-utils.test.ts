import { describe, it, expect } from 'vitest';
import { Hash, Utils } from '@bsv/sdk';
import { buildP2PKHScript, extractConstructorArgs, matchesArtifact } from '../script-utils.js';
import { MalformedScriptError } from '../errors.js';

// ---------------------------------------------------------------------------
// buildP2PKHScript — single consolidated P2PKH script builder
// ---------------------------------------------------------------------------

describe('buildP2PKHScript', () => {
  // A known 20-byte pubkey hash (hex)
  const knownHash160 = 'aabbccddee11223344556677889900aabbccddee';

  it('40-char hex input treated as raw hash160', () => {
    const script = buildP2PKHScript(knownHash160);
    expect(script).toBe('76a914' + knownHash160 + '88ac');
  });

  it('66-char compressed public key is auto-hashed', () => {
    // A real compressed public key (33 bytes = 66 hex chars)
    const compressedPubKey =
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    const expectedHash = Utils.toHex(
      Hash.hash160(Utils.toArray(compressedPubKey, 'hex')),
    );

    const script = buildP2PKHScript(compressedPubKey);
    expect(script).toBe('76a914' + expectedHash + '88ac');
    expect(script.length).toBe(50); // 76a914 (6) + 40 + 88ac (4) = 50
  });

  it('130-char uncompressed public key is auto-hashed', () => {
    // A real uncompressed public key (65 bytes = 130 hex chars)
    const uncompressedPubKey =
      '04' +
      '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' +
      '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
    const expectedHash = Utils.toHex(
      Hash.hash160(Utils.toArray(uncompressedPubKey, 'hex')),
    );

    const script = buildP2PKHScript(uncompressedPubKey);
    expect(script).toBe('76a914' + expectedHash + '88ac');
  });

  it('Base58Check address is decoded correctly', () => {
    // Use a known mainnet address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
    const address = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
    const script = buildP2PKHScript(address);

    // Script should be 50 chars: 76a914 + 40 hex chars + 88ac
    expect(script).toMatch(/^76a914[0-9a-f]{40}88ac$/);
  });

  it('all output formats produce valid P2PKH scripts', () => {
    const inputs = [
      knownHash160,
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
    ];

    for (const input of inputs) {
      const script = buildP2PKHScript(input);
      expect(script).toMatch(/^76a914[0-9a-f]{40}88ac$/);
    }
  });

  it('compressed pubkey and its hash160 produce the same script', () => {
    const pubKey =
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    const hash160 = Utils.toHex(Hash.hash160(Utils.toArray(pubKey, 'hex')));

    expect(buildP2PKHScript(pubKey)).toBe(buildP2PKHScript(hash160));
  });
});

// ---------------------------------------------------------------------------
// extractConstructorArgs — repeated constructor-slot references
// ---------------------------------------------------------------------------

describe('extractConstructorArgs with repeated slot references', () => {
  // A param referenced N times in the contract body emits N constructor
  // slots. Every occurrence's encoded width shifts the offsets of everything
  // after it, so the extractor must account for ALL occurrences — not just
  // the first per param. Regression for a bug where slots were deduplicated
  // by paramIndex BEFORE the offset walk, mis-reading every later slot
  // whenever an earlier repeated value encoded wider than its 1-byte
  // template placeholder.
  //
  // Template: ab <00> 7c <00> 7c <00> ac
  //   offset 1: alpha (paramIndex 0)
  //   offset 3: alpha again (paramIndex 0 — second reference)
  //   offset 5: beta  (paramIndex 1)
  // Resolved with alpha = 500n (scriptnum push `02f401`, 3 bytes) and
  // beta = 7n (OP_7, 1 byte):
  //   ab 02f401 7c 02f401 7c 57 ac
  const artifact = {
    script: 'ab' + '00' + '7c' + '00' + '7c' + '00' + 'ac',
    constructorSlots: [
      { paramIndex: 0, byteOffset: 1, name: 'alpha', type: 'bigint' },
      { paramIndex: 0, byteOffset: 3, name: 'alpha', type: 'bigint' },
      { paramIndex: 1, byteOffset: 5, name: 'beta', type: 'bigint' },
    ],
    abi: {
      constructor: {
        params: [
          { name: 'alpha', type: 'bigint' },
          { name: 'beta', type: 'bigint' },
        ],
      },
    },
  };

  it('reads slots AFTER a repeated wide value at the correct offsets', () => {
    const resolved = 'ab' + '02f401' + '7c' + '02f401' + '7c' + '57' + 'ac';
    const args = extractConstructorArgs(artifact as never, resolved);
    expect(args.alpha).toBe(500n);
    // Before the fix, the second alpha occurrence's +2 byte shift was
    // dropped, so beta was read from inside the second alpha push and
    // decoded as 124n instead of 7n.
    expect(args.beta).toBe(7n);
  });

  it('still extracts correctly when the repeated value fits its placeholder width', () => {
    // alpha = 5n → OP_5 (1 byte, same width as the placeholder: zero shift).
    const resolved = 'ab' + '55' + '7c' + '55' + '7c' + '57' + 'ac';
    const args = extractConstructorArgs(artifact as never, resolved);
    expect(args.alpha).toBe(5n);
    expect(args.beta).toBe(7n);
  });
});

// ---------------------------------------------------------------------------
// F-238 — readScriptElement must refuse malformed provider-supplied scripts
// ---------------------------------------------------------------------------
//
// This is the TS reference `readScriptElement` (not exported) that the
// Python port (`_read_script_element`) mirrors. Before this fix it was
// ALSO fail-open: an empty/out-of-range offset produced `opcode = NaN` and
// fell through to the single-byte-opcode default instead of throwing, and a
// push whose declared length ran past the end of the hex string was handed
// to `.slice()`, which silently returns whatever is left instead of erroring.
//
// PROVES: every malformed vector below throws MalformedScriptError via the
// public entry points (extractConstructorArgs / matchesArtifact — the only
// two callers), and a valid push of every flavour still decodes unchanged.
// DOES NOT PROVE: fail-closed behaviour of any OTHER script reader in the
// SDK (e.g. the OP_RETURN state-section decoder has its own tests).
describe('extractConstructorArgs / matchesArtifact refuse malformed scripts (F-238)', () => {
  const oneSlotArtifact = {
    script: '00' + 'ac',
    constructorSlots: [{ paramIndex: 0, byteOffset: 0, name: 'x', type: 'bigint' }],
    abi: { constructor: { params: [{ name: 'x', type: 'bigint' }] } },
  };

  const malformedVectors = [
    '',             // no opcode byte at all
    'f',            // odd-length hex, can't even form an opcode byte
    '05aabb',       // direct push declares 5 bytes, only 2 remain
    '4c',           // OP_PUSHDATA1 with no length byte
    '4c05aa',       // OP_PUSHDATA1 declares 5 bytes, only 1 remains
    '4d0100',       // OP_PUSHDATA2 length prefix present, 0 of the 1 declared bytes remain
    '4e01000000',   // OP_PUSHDATA4 length prefix present, 0 of the 1 declared bytes remain
  ];

  it.each(malformedVectors)('extractConstructorArgs throws MalformedScriptError for %j', (hex) => {
    expect(() => extractConstructorArgs(oneSlotArtifact as never, hex)).toThrow(MalformedScriptError);
  });

  it.each(malformedVectors)('matchesArtifact throws MalformedScriptError for %j', (hex) => {
    expect(() => matchesArtifact(oneSlotArtifact as never, hex)).toThrow(MalformedScriptError);
  });

  it('still extracts a valid OP_PUSHDATA1/2/4 push with an exact length', () => {
    const pd1 = { script: '00ac', constructorSlots: [{ paramIndex: 0, byteOffset: 0, name: 'x', type: 'ByteString' }], abi: { constructor: { params: [{ name: 'x', type: 'ByteString' }] } } };
    expect(extractConstructorArgs(pd1 as never, '4c012a' + 'ac').x).toBe('2a');
    expect(extractConstructorArgs(pd1 as never, '4d01002a' + 'ac').x).toBe('2a');
    expect(extractConstructorArgs(pd1 as never, '4e010000002a' + 'ac').x).toBe('2a');
  });
});
