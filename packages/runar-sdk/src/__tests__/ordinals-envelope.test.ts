import { describe, it, expect } from 'vitest';
import {
  buildInscriptionEnvelope,
  parseInscriptionEnvelope,
  findInscriptionEnvelope,
  stripInscriptionEnvelope,
} from '../ordinals/envelope.js';

/** Convert a UTF-8 string to hex. */
function utf8ToHex(str: string): string {
  return Array.from(new TextEncoder().encode(str))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('buildInscriptionEnvelope', () => {
  it('builds a text inscription envelope', () => {
    const contentType = 'text/plain';
    const data = utf8ToHex('Hello, ordinals!');
    const envelope = buildInscriptionEnvelope(contentType, data);

    // Starts with OP_FALSE OP_IF PUSH3 "ord" OP_1
    expect(envelope.startsWith('006303' + '6f7264' + '51')).toBe(true);
    // Ends with OP_ENDIF
    expect(envelope.endsWith('68')).toBe(true);
    // Contains content type
    expect(envelope).toContain(utf8ToHex(contentType));
    // Contains data
    expect(envelope).toContain(data);
  });

  it('builds an envelope with large data (OP_PUSHDATA2)', () => {
    const contentType = 'image/png';
    // 300 bytes of data, triggers OP_PUSHDATA2 (> 255 bytes)
    const data = 'ff'.repeat(300);
    const envelope = buildInscriptionEnvelope(contentType, data);

    // Should contain OP_PUSHDATA2 (4d) for the data push
    // The data is 300 bytes = 0x012c LE = 2c01
    expect(envelope).toContain('4d' + '2c01' + data);
    // Still valid envelope
    expect(envelope.startsWith('006303' + '6f7264' + '51')).toBe(true);
    expect(envelope.endsWith('68')).toBe(true);
  });

  it('builds an envelope with medium data (OP_PUSHDATA1)', () => {
    // 100 bytes, triggers OP_PUSHDATA1 (> 75 bytes, <= 255)
    const data = 'ab'.repeat(100);
    const envelope = buildInscriptionEnvelope('application/octet-stream', data);

    // Should contain OP_PUSHDATA1 (4c) for the data push: 100 = 0x64
    expect(envelope).toContain('4c' + '64' + data);
  });

  it('handles empty data with OP_0', () => {
    const envelope = buildInscriptionEnvelope('text/plain', '');
    // Data push is OP_0 (00)
    // Pattern: ... OP_0(delimiter) OP_0(data) OP_ENDIF
    // The last bytes should be: 00 00 68
    expect(envelope.endsWith('000068')).toBe(true);
  });
});

describe('parseInscriptionEnvelope', () => {
  it('round-trips a text inscription', () => {
    const original = { contentType: 'text/plain', data: utf8ToHex('Hello!') };
    const envelope = buildInscriptionEnvelope(original.contentType, original.data);
    const parsed = parseInscriptionEnvelope(envelope);

    expect(parsed).not.toBeNull();
    expect(parsed!.contentType).toBe('text/plain');
    expect(parsed!.data).toBe(original.data);
  });

  it('round-trips a BSV-20 JSON inscription', () => {
    const json = JSON.stringify({ p: 'bsv-20', op: 'deploy', tick: 'TEST', max: '21000000' });
    const original = { contentType: 'application/bsv-20', data: utf8ToHex(json) };
    const envelope = buildInscriptionEnvelope(original.contentType, original.data);
    const parsed = parseInscriptionEnvelope(envelope);

    expect(parsed).not.toBeNull();
    expect(parsed!.contentType).toBe('application/bsv-20');
    expect(parsed!.data).toBe(original.data);
  });

  it('round-trips large data (OP_PUSHDATA2)', () => {
    const data = 'ff'.repeat(300);
    const original = { contentType: 'image/png', data };
    const envelope = buildInscriptionEnvelope(original.contentType, original.data);
    const parsed = parseInscriptionEnvelope(envelope);

    expect(parsed).not.toBeNull();
    expect(parsed!.contentType).toBe('image/png');
    expect(parsed!.data).toBe(data);
  });

  it('returns null for script without envelope', () => {
    const script = 'a914' + '00'.repeat(20) + '87'; // P2SH-like
    expect(parseInscriptionEnvelope(script)).toBeNull();
  });

  it('parses envelope embedded in a larger script', () => {
    const prefix = 'a914' + '00'.repeat(20) + '8788ac'; // some contract code
    const data = utf8ToHex('test');
    const envelope = buildInscriptionEnvelope('text/plain', data);
    const suffix = '6a' + '08' + '00'.repeat(8); // OP_RETURN + state

    const fullScript = prefix + envelope + suffix;
    const parsed = parseInscriptionEnvelope(fullScript);

    expect(parsed).not.toBeNull();
    expect(parsed!.contentType).toBe('text/plain');
    expect(parsed!.data).toBe(data);
  });
});

describe('findInscriptionEnvelope', () => {
  it('finds envelope bounds in a script', () => {
    const prefix = 'aabb';
    const envelope = buildInscriptionEnvelope('text/plain', utf8ToHex('hi'));
    const suffix = 'ccdd';

    const script = prefix + envelope + suffix;
    const bounds = findInscriptionEnvelope(script);

    expect(bounds).not.toBeNull();
    expect(bounds!.startHex).toBe(prefix.length);
    expect(bounds!.endHex).toBe(prefix.length + envelope.length);
  });

  it('returns null when no envelope present', () => {
    expect(findInscriptionEnvelope('76a914' + '00'.repeat(20) + '88ac')).toBeNull();
  });

  it('finds envelope between code and OP_RETURN for stateful scripts', () => {
    const code = '76a914' + '00'.repeat(20) + '88ac';
    const envelope = buildInscriptionEnvelope('text/plain', utf8ToHex('ord'));
    const state = '6a' + '08' + '0000000000000000'; // OP_RETURN + 8 bytes

    const fullScript = code + envelope + state;
    const bounds = findInscriptionEnvelope(fullScript);

    expect(bounds).not.toBeNull();
    expect(bounds!.startHex).toBe(code.length);
    expect(bounds!.endHex).toBe(code.length + envelope.length);
  });
});

describe('stripInscriptionEnvelope', () => {
  it('removes the envelope and preserves surrounding script', () => {
    const prefix = 'aabb';
    const envelope = buildInscriptionEnvelope('text/plain', utf8ToHex('hi'));
    const suffix = 'ccdd';

    const stripped = stripInscriptionEnvelope(prefix + envelope + suffix);
    expect(stripped).toBe(prefix + suffix);
  });

  it('returns the script unchanged if no envelope', () => {
    const script = '76a914' + '00'.repeat(20) + '88ac';
    expect(stripInscriptionEnvelope(script)).toBe(script);
  });
});
