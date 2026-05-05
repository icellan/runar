/**
 * Runtime vectors — cross-SDK consistency check.
 *
 * Loads `conformance/runtime-vectors/hashes.json` (the cross-SDK source of
 * truth for `sha256Finalize`, `blake3Compress`, and `blake3Hash` outputs)
 * and asserts that the TS SDK's compiled-script runtime produces the
 * documented output byte-for-byte. Every other consumer (Java, Python, Go,
 * Rust, Zig, Ruby) loads the same file and runs the equivalent assertion;
 * a divergence between any two runtimes shows up here.
 *
 * Reference: conformance/runtime-vectors/README.md (if present) — and
 * `_consumers` in the JSON file itself, which enumerates the per-SDK tests
 * that share these vectors.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ScriptExecutionContract } from '../script-execution.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = resolve(
  __dirname,
  '../../../../conformance/runtime-vectors/hashes.json',
);

interface Sha256FinalizeVector {
  name: string;
  state: string;
  remaining: string;
  msg_bit_len: number;
  expected: string;
}

interface Blake3HashVector {
  name: string;
  input: string;
  expected: string;
}

interface Blake3CompressVector {
  name: string;
  state: string;
  block: string;
  expected: string;
  _doc?: string;
}

interface RuntimeVectors {
  constants: { sha256_iv: string; blake3_iv: string };
  sha256_finalize: Sha256FinalizeVector[];
  blake3_hash: Blake3HashVector[];
  blake3_compress: Blake3CompressVector[];
}

const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as RuntimeVectors;

// Compiled contract sources. Each takes a single ByteString constructor
// arg `expected` and a verify method that calls the runtime helper and
// asserts its result equals `expected`. ScriptExecutionContract compiles +
// executes through the BSV SDK interpreter — the canonical TS-side runtime.

const SHA256_FINALIZE_SOURCE = `
class Sha256FinalizeTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
    const result = sha256Finalize(state, remaining, msgBitLen);
    assert(result === this.expected);
  }
}
`;

const BLAKE3_COMPRESS_SOURCE = `
class Blake3CompressTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(chainingValue: ByteString, block: ByteString) {
    const result = blake3Compress(chainingValue, block);
    assert(result === this.expected);
  }
}
`;

const BLAKE3_HASH_SOURCE = `
class Blake3HashTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(message: ByteString) {
    const result = blake3Hash(message);
    assert(result === this.expected);
  }
}
`;

describe('Runtime vectors — sha256Finalize (loaded from hashes.json)', () => {
  for (const v of vectors.sha256_finalize) {
    it(`sha256Finalize: ${v.name}`, () => {
      const contract = ScriptExecutionContract.fromSource(
        SHA256_FINALIZE_SOURCE,
        { expected: v.expected },
        'Sha256FinalizeTest.runar.ts',
      );
      const result = contract.execute('verify', [
        v.state,
        v.remaining,
        BigInt(v.msg_bit_len),
      ]);
      expect(result.success, result.error).toBe(true);
    });
  }
});

describe('Runtime vectors — blake3Compress (loaded from hashes.json)', () => {
  for (const v of vectors.blake3_compress) {
    it(`blake3Compress: ${v.name}`, () => {
      const contract = ScriptExecutionContract.fromSource(
        BLAKE3_COMPRESS_SOURCE,
        { expected: v.expected },
        'Blake3CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [v.state, v.block]);
      expect(result.success, result.error).toBe(true);
    });
  }
});

describe('Runtime vectors — blake3Hash (loaded from hashes.json)', () => {
  for (const v of vectors.blake3_hash) {
    it(`blake3Hash: ${v.name}`, () => {
      // The TS BLAKE3 codegen hardcodes blockLen=64 in the compressed
      // state, so blake3Hash(message) zero-pads `message` to 64 bytes
      // before feeding it into the single-block compression. The JSON
      // golden's `expected` field is the canonical BLAKE3 hash for the
      // raw input, which matches the on-chain compute for inputs ≤ 64 B.
      const contract = ScriptExecutionContract.fromSource(
        BLAKE3_HASH_SOURCE,
        { expected: v.expected },
        'Blake3HashTest.runar.ts',
      );
      const result = contract.execute('verify', [v.input]);
      expect(result.success, result.error).toBe(true);
    });
  }
});

describe('Runtime vectors — constants', () => {
  it('blake3_iv matches sha256_iv (intentional design choice)', () => {
    // Both BLAKE3 and SHA-256 use the same 8-word IV in their compression
    // function: BLAKE3 deliberately reuses the SHA-256 IV. The JSON file
    // captures this so any consumer SDK that builds its own constant table
    // catches a typo by comparing against this row.
    expect(vectors.constants.blake3_iv).toBe(vectors.constants.sha256_iv);
  });
});
