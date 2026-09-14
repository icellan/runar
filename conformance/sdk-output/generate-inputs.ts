import { execFileSync } from 'child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { join, basename, dirname, resolve, relative } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '../..');
const TESTS_DIR = join(__dirname, 'tests');
const CONFORMANCE_TESTS_DIR = join(ROOT, 'conformance/tests');
// Reuse the loader that is already executing this TypeScript generator. This
// works for both a workspace-local tsx and the temporary package installed by
// `npx tsx`, without a second package-manager invocation or module lookup.
const TSX_NODE_ARGS = process.execArgv;

interface TestSpec {
  name: string;
  /**
   * Repo-root-relative path to a `.runar.ts` source. If omitted, resolved
   * via conformance/tests/<name>/source.json's `.runar.ts` entry. Conformance
   * cases no longer host their own contracts — they reference examples/.
   */
  source?: string;
  constructorArgs: Array<{ type: string; value: string }>;
}

/** Resolve a TestSpec's source path. Reads source.json when source is absent. */
function resolveTestSource(spec: TestSpec): string {
  if (spec.source) return spec.source;
  const configPath = join(CONFORMANCE_TESTS_DIR, spec.name, 'source.json');
  if (!existsSync(configPath)) {
    throw new Error(`No source for spec '${spec.name}': missing ${configPath}`);
  }
  const cfg = JSON.parse(readFileSync(configPath, 'utf-8')) as {
    sources?: Record<string, string>;
    path?: string;
  };
  const tsRel = cfg.sources?.['.runar.ts'] ?? (cfg.path?.endsWith('.runar.ts') ? cfg.path : undefined);
  if (!tsRel) {
    throw new Error(`No .runar.ts source for spec '${spec.name}' in ${configPath}`);
  }
  const abs = resolve(dirname(configPath), tsRel);
  return relative(ROOT, abs);
}

// Standard test values
const PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const ADDR = '751e76e8199196d454941c45d1b3a323f1433bd6';
const ALT_ADDR = '89abcdefabbaabbaabbaabbaabbaabbaabbaabba';
const HASH32 = '0000000000000000000000000000000000000000000000000000000000000001';
const POINT = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
const HELLO = '48656c6c6f';
// A 1-byte ByteString whose value is in the OP_1..OP_16 range. Serialised into
// the state section it must stay the direct push `01 05`, NOT the MINIMALDATA
// opcode `55` — the state section is raw data after OP_RETURN, never executed,
// and the compiler's on-chain reader only understands <len><data>.
const ONE_BYTE_OP_N = '05';
// NIST P-256 generator point (64 bytes: x[32] || y[32], big-endian).
const P256_POINT = '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
// NIST P-384 generator point (96 bytes: x[48] || y[48], big-endian).
const P384_POINT = 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f';
// SHA-256(33-byte compressed P-256 PK) — placeholder hash for wallet contracts.
const P256_PKHASH = '0000000000000000000000000000000000000000000000000000000000000002';
// SHA-256(49-byte compressed P-384 PK) — placeholder hash for wallet contracts.
const P384_PKHASH = '0000000000000000000000000000000000000000000000000000000000000003';

const TEST_SPECS: TestSpec[] = [
  // ===== Example contracts (examples/ts/) =====

  {
    name: 'all-readonly-cleanstack',
    constructorArgs: [
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'auction',
    source: 'examples/ts/auction/Auction.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '0' },
      { type: 'bigint', value: '1000000' },
    ],
  },
  {
    name: 'babybear',
    source: 'examples/ts/babybear/BabyBearDemo.runar.ts',
    constructorArgs: [],
  },
  {
    name: 'blake3',
    source: 'examples/ts/blake3/Blake3Test.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'convergence-proof',
    source: 'examples/ts/convergence-proof/ConvergenceProof.runar.ts',
    constructorArgs: [
      { type: 'Point', value: POINT },
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'covenant-vault',
    source: 'examples/ts/covenant-vault/CovenantVault.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'Addr', value: ADDR },
      { type: 'bigint', value: '10000' },
    ],
  },
  {
    name: 'cross-covenant',
    source: 'examples/ts/cross-covenant/CrossCovenantRef.runar.ts',
    constructorArgs: [
      { type: 'Sha256', value: HASH32 },
    ],
  },
  {
    name: 'ec-demo',
    source: 'examples/ts/ec-demo/ECDemo.runar.ts',
    constructorArgs: [
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'escrow',
    source: 'examples/ts/escrow/Escrow.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'function-patterns',
    source: 'examples/ts/function-patterns/FunctionPatterns.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '1000' },
    ],
  },
  {
    name: 'math-demo',
    source: 'examples/ts/math-demo/MathDemo.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '100' },
    ],
  },
  {
    name: 'merkle-proof',
    source: 'examples/ts/merkle-proof/MerkleProofDemo.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'message-board',
    source: 'examples/ts/message-board/MessageBoard.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HELLO },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'oracle-price',
    source: 'examples/ts/oracle-price/OraclePriceFeed.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '12345678901234567890' },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'p2blake3pkh',
    source: 'examples/ts/p2blake3pkh/P2Blake3PKH.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'p2pkh',
    source: 'examples/ts/p2pkh/P2PKH.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
    ],
  },
  {
    name: 'post-quantum-wallet',
    source: 'examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'property-initializers',
    source: 'examples/ts/property-initializers/BoundedCounter.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '100' },
    ],
  },
  {
    name: 'schnorr-zkp',
    source: 'examples/ts/schnorr-zkp/SchnorrZKP.runar.ts',
    constructorArgs: [
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'sha256-compress',
    source: 'examples/ts/sha256-compress/Sha256CompressTest.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'sha256-finalize',
    source: 'examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'sphincs-wallet',
    source: 'examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'p256-primitives',
    source: 'examples/ts/p256-primitives/P256Primitives.runar.ts',
    constructorArgs: [
      { type: 'P256Point', value: P256_POINT },
    ],
  },
  {
    name: 'p256-wallet',
    source: 'examples/ts/p256-wallet/P256Wallet.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
      { type: 'ByteString', value: P256_PKHASH },
    ],
  },
  {
    name: 'r1-k1-wallet',
    source: 'examples/ts/r1-k1-wallet/R1K1Wallet.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
      { type: 'Addr', value: ALT_ADDR },
    ],
  },
  {
    name: 'p384-primitives',
    source: 'examples/ts/p384-primitives/P384Primitives.runar.ts',
    constructorArgs: [
      { type: 'P384Point', value: P384_POINT },
    ],
  },
  {
    name: 'p384-wallet',
    source: 'examples/ts/p384-wallet/P384Wallet.runar.ts',
    constructorArgs: [
      { type: 'Addr', value: ADDR },
      { type: 'ByteString', value: P384_PKHASH },
    ],
  },
  {
    name: 'state-covenant',
    source: 'examples/ts/state-covenant/StateCovenant.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
      { type: 'bigint', value: '0' },
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'stateful-counter',
    source: 'examples/ts/stateful-counter/Counter.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '0' },
    ],
  },
  // R-248: the corpus's only MUTABLE `boolean` state field. The compiler
  // spells the type `boolean` (never `bool`) and annotates it
  // `encoding: "bool1", byteLength: 1`; five of the seven SDKs matched only
  // on the spelling `bool` and mis-encoded the canonical one three different
  // ways. Both polarities are pinned: two of the five wrote a constant `00`
  // regardless of the value, and a false-only fixture would have let them
  // through.
  {
    name: 'stateful-boolean-true',
    source: 'conformance/sdk-output/contracts/StatefulFlag.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '7' },
      { type: 'boolean', value: 'true' },
    ],
  },
  {
    name: 'stateful-boolean-false',
    source: 'conformance/sdk-output/contracts/StatefulFlag.runar.ts',
    constructorArgs: [
      { type: 'bigint', value: '7' },
      { type: 'boolean', value: 'false' },
    ],
  },
  {
    name: 'tic-tac-toe',
    source: 'examples/ts/tic-tac-toe/TicTacToe.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '10000' },
    ],
  },
  {
    name: 'token-ft',
    source: 'examples/ts/token-ft/FungibleTokenExample.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'bigint', value: '1000' },
      { type: 'bigint', value: '0' },
      { type: 'ByteString', value: HELLO },
    ],
  },
  {
    name: 'token-nft',
    source: 'examples/ts/token-nft/NFTExample.runar.ts',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'ByteString', value: HELLO },
      { type: 'ByteString', value: HELLO },
    ],
  },

  // ===== Conformance contracts (source resolved via source.json → examples/) =====

  {
    name: 'arithmetic',
    constructorArgs: [
      { type: 'bigint', value: '42' },
    ],
  },
  {
    name: 'babybear-ext4',
    constructorArgs: [],
  },
  {
    name: 'basic-p2pkh',
    constructorArgs: [
      { type: 'Addr', value: '89abcdefabbaabbaabbaabbaabbaabbaabbaabba' },
    ],
  },
  {
    name: 'boolean-logic',
    constructorArgs: [
      { type: 'bigint', value: '10' },
    ],
  },
  {
    name: 'bounded-loop',
    constructorArgs: [
      { type: 'bigint', value: '25' },
    ],
  },
  {
    name: 'ec-primitives',
    constructorArgs: [
      { type: 'Point', value: POINT },
    ],
  },
  {
    name: 'if-else',
    constructorArgs: [
      { type: 'bigint', value: '10' },
    ],
  },
  {
    name: 'if-without-else',
    constructorArgs: [
      { type: 'bigint', value: '5' },
    ],
  },
  {
    name: 'multi-method',
    constructorArgs: [
      { type: 'PubKey', value: PK },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    name: 'post-quantum-slhdsa',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'post-quantum-wots',
    constructorArgs: [
      { type: 'ByteString', value: HASH32 },
    ],
  },
  {
    name: 'stateful',
    constructorArgs: [
      { type: 'bigint', value: '0' },
      { type: 'bigint', value: '100' },
    ],
  },
  {
    // The branch-merged-local regression fixture. Deployed-locking-script
    // parity across all seven SDKs for a contract whose compiled script
    // exercises the merged-local result block.
    name: 'branch-merged-locals',
    constructorArgs: [
      { type: 'bigint', value: '0' },
      { type: 'bigint', value: '0' },
    ],
  },
  {
    name: 'stateful-bytestring',
    constructorArgs: [
      { type: 'ByteString', value: HELLO },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    // Same contract as `stateful-bytestring`, but the ByteString state field
    // holds a SINGLE byte in the OP_1..OP_16 range. That is the one value
    // class where the state serializer used to disagree with the compiler's
    // on-chain state codec: #110 taught all seven SDKs the MINIMALDATA push
    // rule (0x05 -> OP_5 = "55"), while every compiler kept writing and
    // parsing <len><data> ("0105"). Any contract carrying such a value became
    // permanently unspendable, and #110's own commit note recorded that no
    // fixture covered it. This is that fixture.
    name: 'stateful-bytestring-op-n-state',
    source: 'examples/ts/message-board/MessageBoard.runar.ts',
    constructorArgs: [
      { type: 'ByteString', value: ONE_BYTE_OP_N },
      { type: 'PubKey', value: PK },
    ],
  },
  {
    // Issue #162. The constructor arg is the sum the contract asserts —
    // 85070591730234615893513767959916445698, a 126-bit value that needs a
    // 16-byte script number. Every other bigint slot in this suite fits a
    // machine word, so nothing here previously spliced a constructor value
    // wider than 8 bytes, and a tier whose slot encoder narrowed to i64
    // would have gone unnoticed. The compiler-side analogue of exactly that
    // narrowing is what #162 fixed in the Zig tier.
    name: 'integer-boundary',
    constructorArgs: [
      { type: 'bigint', value: '85070591730234615893513767959916445698' },
    ],
  },
];

const TMP_DIR = join(__dirname, '.tmp');
if (!existsSync(TMP_DIR)) mkdirSync(TMP_DIR, { recursive: true });

/**
 * `--check`: recompile every spec and FAIL if the checked-in input.json
 * differs from what the compiler produces today, instead of rewriting it.
 *
 * Why this mode has to exist. `input.json` embeds a FROZEN artifact, and
 * sdk-runner compares the seven SDKs against `expected-locking.hex` built
 * from that artifact. Nothing tied either file to the current compiler, so
 * a codegen change that moved bytes left the pair internally consistent and
 * the suite green — while silently testing seven-SDK agreement on a script
 * the compiler no longer emits.
 *
 * That is not hypothetical. Four fixtures had drifted this way before this
 * flag existed: boolean-logic still carried the 15-byte pre-NEW-014 script
 * where the compiler now emits 36, and post-quantum-slhdsa, sphincs-wallet
 * and tic-tac-toe carried pre-Any-S artifacts (#161). Each was found only
 * by regenerating by hand and noticing the diff.
 *
 * Mirrors `sdk-vertical:check`, which guards its own fixtures the same way.
 */
const CHECK_ONLY = process.argv.includes('--check');
const drifted: string[] = [];

for (const spec of TEST_SPECS) {
  let sourceRel: string;
  try {
    sourceRel = resolveTestSource(spec);
  } catch (err: any) {
    console.error(`  ${err.message}`);
    continue;
  }
  const sourcePath = join(ROOT, sourceRel);
  console.log(`Compiling ${spec.name} (${sourceRel})...`);
  try {
    execFileSync(
      process.execPath,
      [
        ...TSX_NODE_ARGS,
        'packages/runar-cli/src/bin.ts',
        'compile',
        sourcePath,
        '-o',
        TMP_DIR,
      ],
      { cwd: ROOT, stdio: 'pipe' },
    );
  } catch (err: any) {
    console.error(`  FAILED to compile ${spec.name}: ${err.stderr?.toString().slice(0, 200)}`);
    continue;
  }

  const sourceBase = basename(sourceRel, '.ts');
  const artifactPath = join(TMP_DIR, `${sourceBase}.json`);
  if (!existsSync(artifactPath)) {
    console.error(`  No artifact found for ${spec.name} at ${artifactPath}`);
    continue;
  }
  const artifact = JSON.parse(readFileSync(artifactPath, 'utf-8'));

  // Strip fields not needed by SDK tools
  delete artifact.ir;
  delete artifact.anf;
  delete artifact.asm;
  delete artifact.sourceMap;
  delete artifact.buildTimestamp;

  const input = { artifact, constructorArgs: spec.constructorArgs };
  const testDir = join(TESTS_DIR, spec.name);
  const inputPath = join(testDir, 'input.json');
  const rendered = JSON.stringify(input, null, 2) + '\n';

  if (CHECK_ONLY) {
    if (!existsSync(inputPath)) {
      drifted.push(`${spec.name} (no input.json on disk)`);
      console.error(`  DRIFT ${spec.name}: input.json missing`);
      continue;
    }
    const onDisk = readFileSync(inputPath, 'utf-8');
    if (onDisk !== rendered) {
      const storedScript = (JSON.parse(onDisk).artifact ?? {}).script ?? '';
      const freshScript = artifact.script ?? '';
      const detail =
        storedScript === freshScript
          ? 'artifact metadata differs'
          : `script ${storedScript.length / 2} B on disk vs ${freshScript.length / 2} B fresh`;
      drifted.push(`${spec.name} (${detail})`);
      console.error(`  DRIFT ${spec.name}: ${detail}`);
    } else {
      console.log(`  ok ${spec.name}`);
    }
    continue;
  }

  if (!existsSync(testDir)) mkdirSync(testDir, { recursive: true });
  writeFileSync(inputPath, rendered);
  console.log(`  Wrote ${spec.name}/input.json`);
}

if (CHECK_ONLY) {
  if (drifted.length > 0) {
    console.error(
      `\n✗ sdk-output input drift: ${drifted.length} fixture(s) carry a FROZEN artifact that the\n` +
        `  compiler no longer produces. expected-locking.hex is derived from that artifact, so the\n` +
        `  seven-SDK comparison for these fixtures is agreeing on a script that is no longer shipped:\n` +
        drifted.map((d) => `    - ${d}`).join('\n') +
        `\n\n  Fix: npx tsx conformance/sdk-output/generate-inputs.ts` +
        `\n       npx tsx conformance/sdk-output/runner/sdk-runner.ts --update-golden` +
        `\n  Regenerate the INPUT first — refreshing only the expected hex compares fresh SDK` +
        `\n  output against a stale codePart and proves nothing.\n`,
    );
    process.exit(1);
  }
  console.log('\n✓ sdk-output inputs match the current compiler.');
} else {
  console.log('\nDone. Run SDK tools to generate expected-locking.hex files.');
}
