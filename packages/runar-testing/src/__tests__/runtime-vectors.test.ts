/**
 * Runtime vectors — cross-SDK consistency check.
 *
 * Loads `conformance/runtime-vectors/hashes.json` (the cross-SDK source of
 * truth for hash runtime outputs) and asserts that direct SHA-256,
 * RIPEMD-160, HASH160, and HASH256 vectors match Node.js `crypto`, the
 * Runar runtime helpers, and compiled-script execution. It also checks
 * the compression-style vectors used by the crypto-heavy Runar builtins.
 *
 * Reference: conformance/runtime-vectors/README.md (if present) — and
 * `_consumers` in the JSON file itself, which enumerates the per-SDK tests
 * that share these vectors.
 */

import { describe, it, expect } from 'vitest';
import { createHash, getHashes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  hash160 as runtimeHash160,
  hash256 as runtimeHash256,
  ripemd160 as runtimeRipemd160,
  sha256 as runtimeSha256,
  toByteString,
} from 'runar-lang/runtime';
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

interface HashVector {
  name: string;
  input: string;
  expected: string;
}

interface RuntimeVectors {
  constants: { sha256_iv: string; blake3_iv: string };
  sha256: HashVector[];
  ripemd160: HashVector[];
  hash160: HashVector[];
  hash256: HashVector[];
  sha256_finalize: Sha256FinalizeVector[];
  blake3_hash: Blake3HashVector[];
  blake3_compress: Blake3CompressVector[];
}

const vectors = JSON.parse(readFileSync(VECTORS_PATH, 'utf8')) as RuntimeVectors;

if (!getHashes().includes('ripemd160')) {
  throw new Error('Node.js crypto does not expose ripemd160');
}

function nodeHash(algorithm: 'sha256' | 'ripemd160', hex: string): string {
  return createHash(algorithm).update(Buffer.from(hex, 'hex')).digest('hex');
}

function nodeHash160(hex: string): string {
  return nodeHash('ripemd160', nodeHash('sha256', hex));
}

function nodeHash256(hex: string): string {
  return nodeHash('sha256', nodeHash('sha256', hex));
}

const HASH_REFERENCE = {
  sha256: (hex: string) => nodeHash('sha256', hex),
  ripemd160: (hex: string) => nodeHash('ripemd160', hex),
  hash160: nodeHash160,
  hash256: nodeHash256,
} as const;

const RUNTIME_HASH = {
  sha256: runtimeSha256,
  ripemd160: runtimeRipemd160,
  hash160: runtimeHash160,
  hash256: runtimeHash256,
} as const;

const HASH_CONTRACT_SOURCE = {
  sha256: `
class Sha256Test extends SmartContract {
  readonly expected: Sha256;

  constructor(expected: Sha256) {
    super(expected);
    this.expected = expected;
  }

  public verify(data: ByteString) {
    const result = sha256(data);
    assert(result === this.expected);
  }
}
`,
  ripemd160: `
class Ripemd160Test extends SmartContract {
  readonly expected: Ripemd160;

  constructor(expected: Ripemd160) {
    super(expected);
    this.expected = expected;
  }

  public verify(data: ByteString) {
    const result = ripemd160(data);
    assert(result === this.expected);
  }
}
`,
  hash160: `
class Hash160Test extends SmartContract {
  readonly expected: Ripemd160;

  constructor(expected: Ripemd160) {
    super(expected);
    this.expected = expected;
  }

  public verify(data: ByteString) {
    const result = hash160(data);
    assert(result === this.expected);
  }
}
`,
  hash256: `
class Hash256Test extends SmartContract {
  readonly expected: Sha256;

  constructor(expected: Sha256) {
    super(expected);
    this.expected = expected;
  }

  public verify(data: ByteString) {
    const result = hash256(data);
    assert(result === this.expected);
  }
}
`,
} as const;

type HashBuiltin = keyof typeof HASH_REFERENCE;

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

describe('Runtime vectors — direct hashes against Node.js crypto', () => {
  for (const builtin of ['sha256', 'ripemd160', 'hash160', 'hash256'] as const) {
    for (const v of vectors[builtin]) {
      it(`${builtin}: ${v.name}`, () => {
        expect(v.expected).toBe(HASH_REFERENCE[builtin](v.input));
      });
    }
  }
});

describe('Runtime vectors — runar-lang hash helpers', () => {
  for (const builtin of ['sha256', 'ripemd160', 'hash160', 'hash256'] as const) {
    for (const v of vectors[builtin]) {
      it(`${builtin}: ${v.name}`, () => {
        const actual = RUNTIME_HASH[builtin](toByteString(v.input));
        expect(actual).toBe(v.expected);
      });
    }
  }
});

describe('Runtime vectors — compiled Script hash opcodes', () => {
  for (const builtin of ['sha256', 'ripemd160', 'hash160', 'hash256'] as const) {
    for (const v of vectors[builtin]) {
      it(`${builtin}: ${v.name}`, () => {
        const contract = ScriptExecutionContract.fromSource(
          HASH_CONTRACT_SOURCE[builtin],
          { expected: v.expected },
          `${contractNameFor(builtin)}.runar.ts`,
        );
        const result = contract.execute('verify', [v.input]);
        expect(result.success, result.error).toBe(true);
      });
    }
  }
});

function contractNameFor(builtin: HashBuiltin): string {
  switch (builtin) {
    case 'sha256':
      return 'Sha256Test';
    case 'ripemd160':
      return 'Ripemd160Test';
    case 'hash160':
      return 'Hash160Test';
    case 'hash256':
      return 'Hash256Test';
  }
}

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
