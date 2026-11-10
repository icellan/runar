/**
 * resolveSlotLayout / computeTemplateHash for a 1-byte ByteString arg that
 * encodeArg writes as a single opcode.
 *
 * encodeArg writes a 1-byte ByteString 0x01..0x10 as OP_1..OP_16 and 0x81 as
 * OP_1NEGATE (minimal push), with no push header. classifyEncoded handled that
 * for bigint args only, so a hex-string arg in that range was classified as a
 * data push with a 5-byte header: valueByteLength -4. computeTemplateHash's
 * excision then kept the opcode and repeated the bytes after it, so two
 * instances differing only in such a value got different template hashes.
 *
 * Proves: these values are classified like the bigint case (no header, one
 * value byte) and share a template hash with each other and with an OP_N
 * bigint; data pushes keep their header in the hash, and their digests are
 * pinned to the values main computes, so only the single-opcode values move;
 * resolveSlotLayout agrees with the reference layout of every
 * conformance/sdk-vertical case (OP_0 slots aside, see below).
 * Does NOT prove: anything about a hash a covenant already baked for such an
 * instance (it keeps its old value), nor anything about the other SDKs, which
 * have no computeTemplateHash.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeTemplateHash, resolveSlotLayout } from '../slot-layout.js';
import type { RunarArtifact } from '../types.js';

const base = {
  version: 'runar-v0.1.0',
  compilerVersion: '0.1.0',
  contractName: 'T',
  asm: '',
  buildTimestamp: '',
  script: '0087',
  constructorSlots: [{ paramIndex: 0, byteOffset: 0 }],
};
/** `<tag> OP_EQUAL` with a ByteString tag. */
const tagA = {
  ...base,
  abi: { constructor: { params: [{ name: 'tag', type: 'ByteString' }] }, methods: [] },
} as unknown as RunarArtifact;
/** The same template with a bigint param. */
const numA = {
  ...base,
  abi: { constructor: { params: [{ name: 'n', type: 'bigint' }] }, methods: [] },
} as unknown as RunarArtifact;

describe('computeTemplateHash: a 1-byte ByteString that bakes as a single opcode', () => {
  it('two instances share a template hash', () => {
    expect(computeTemplateHash(tagA, ['05'])).toBe(computeTemplateHash(tagA, ['06']));
    expect(computeTemplateHash(tagA, ['01'])).toBe(computeTemplateHash(tagA, ['10']));
    expect(computeTemplateHash(tagA, ['81'])).toBe(computeTemplateHash(tagA, ['05']));
    expect(computeTemplateHash(tagA, ['01'])).toBe(computeTemplateHash(tagA, ['05']));
  });

  it('the hash equals that of an OP_N bigint and of OP_0 (opcode excised whole)', () => {
    expect(computeTemplateHash(tagA, ['05'])).toBe(computeTemplateHash(numA, [5n]));
    expect(computeTemplateHash(tagA, ['05'])).toBe(computeTemplateHash(tagA, ['']));
  });

  it('the layout reports the single opcode as the value byte', () => {
    for (const tag of ['01', '10', '81']) {
      const [s] = resolveSlotLayout(tagA, [tag]).slots;
      expect(s).toMatchObject({ byteLength: 1, pushHeaderBytes: 0, valueByteOffset: 0, valueByteLength: 1 });
      expect(s!.encoding).toBe(tag === '81' ? 'op-1negate' : 'op-n');
    }
  });
});

describe('computeTemplateHash: other values are unchanged', () => {
  // Digests computed with the SDK before this change (runar main 419e8ab91).
  it.each([
    ['aa', 'e7184f3676db1a72f299318df080fcfc3f74e6b9d4e0f9e1a429af1f54d96604'],
    ['11', 'e7184f3676db1a72f299318df080fcfc3f74e6b9d4e0f9e1a429af1f54d96604'],
    ['00', 'e7184f3676db1a72f299318df080fcfc3f74e6b9d4e0f9e1a429af1f54d96604'],
    ['aabb', 'b339bce7e531517ac14299e6d7e3af15674edc96efedf39e1647a452909cad9b'],
    ['', '71f3da85de562cc0f695fe18e7fec054d9f6cd388c3a72d7cd4725cf4ca0c13b'],
  ])('ByteString %j', (tag, digest) => {
    expect(computeTemplateHash(tagA, [tag])).toBe(digest);
  });

  it.each([
    [5n, '71f3da85de562cc0f695fe18e7fec054d9f6cd388c3a72d7cd4725cf4ca0c13b'],
    [17n, 'e7184f3676db1a72f299318df080fcfc3f74e6b9d4e0f9e1a429af1f54d96604'],
  ])('bigint %s', (n, digest) => {
    expect(computeTemplateHash(numA, [n])).toBe(digest);
  });

  it('a data push keeps its header, so a 1-byte push and a single opcode differ', () => {
    expect(computeTemplateHash(tagA, ['aa'])).toBe(computeTemplateHash(tagA, ['bb']));
    expect(computeTemplateHash(tagA, ['aa'])).not.toBe(computeTemplateHash(tagA, ['05']));
  });
});

describe('resolveSlotLayout agrees with the sdk-vertical reference layout', () => {
  // conformance/sdk-vertical derives each slot's header/value split from the
  // compiler's artifact without the SDK. OP_0 is left out: the reference
  // counts it as zero value bytes, while resolveSlotLayout reports the opcode
  // itself as the value (and the template hash excises it); this change does
  // not touch that.
  const isOp0 = (s: { byteLength: number; valueByteLength: number }) => s.byteLength === 1 && s.valueByteLength === 0;
  const casesDir = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../conformance/sdk-vertical/cases');
  const typed = (a: { type: string; value: string }): unknown =>
    a.type === 'bigint' ? BigInt(a.value) : a.type === 'bool' ? a.value === 'true' : a.value.toLowerCase();
  for (const name of readdirSync(casesDir).sort()) {
    it(name, () => {
      const input = JSON.parse(readFileSync(resolve(casesDir, name, 'input.json'), 'utf8'));
      const expected = JSON.parse(readFileSync(resolve(casesDir, name, 'expected-vertical.json'), 'utf8'));
      const { slots } = resolveSlotLayout(input.artifact, input.constructorArgs.map(typed));
      const want = expected.slots as Array<Record<string, number>>;
      expect(slots.length).toBe(want.length);
      const keep = want.map((s) => !isOp0(s as { byteLength: number; valueByteLength: number }));
      expect(slots.filter((_, i) => keep[i]).map((s) =>
        [s.templateByteOffset, s.byteOffset, s.byteLength, s.pushHeaderBytes, s.valueByteOffset, s.valueByteLength]))
        .toEqual(want.filter((_, i) => keep[i]).map((s) =>
          [s.templateByteOffset, s.byteOffset, s.byteLength, s.headerBytes, s.valueByteOffset, s.valueByteLength]));
    });
  }
});
