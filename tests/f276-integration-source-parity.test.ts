/**
 * F-276: integration/java and integration/ruby used to broadcast
 * TypeScript-compiler artifacts for every contract, not native-compiler
 * hex — `ContractCompiler.java` shelled every compile out to `npx tsx`
 * running the TS reference compiler, and `compile_contract` in
 * integration/ruby/spec/spec_helper.rb fell back to the same TS compiler
 * (via Node) for every source that was not a `.runar.rb` file. Both were
 * switched to their own tier's native compiler (compilers/java's
 * `--emit-artifact`, compilers/ruby's `--source`).
 *
 * This is the durable, offline proof that switch was safe: every distinct
 * source path either integration suite compiles is compiled here with
 * both the native tier and the TS reference compiler (in-process, fold-ON
 * — the default both `runar-compiler-ruby --source` and the Java CLI's
 * `--emit-artifact` path use, matching what the integration suites
 * actually deploy), and the resulting `script` hex is compared.
 *
 * Most of these paths are also conformance fixtures (`conformance/tests/`)
 * and already byte-pinned there. The ones that are NOT — TicTacToe,
 * MessageBoard, BSV20Token, BSV21Token, OrdinalNFT, and every fixture
 * under `integration/contracts/` — have no golden anywhere else; this
 * file is their only proof. Without it, three now-committed comments
 * (`ContractCompiler.java`, `spec_helper.rb`, `compiler_provenance_spec.rb`)
 * would cite evidence that existed only as a throwaway shell script in a
 * remediation log, never committed.
 *
 * StateCovenant is excluded from the Java list and checked separately:
 * the Java compiler deliberately REFUSES it (it calls `bbFieldMul`, a
 * BabyBear builtin that is Go-only by project policy — see CLAUDE.md
 * "Go-only crypto codegen modules"), so `ContractCompiler.java` carries a
 * named exception (`TS_REFERENCE_ONLY`) routing it to the TS compiler
 * instead. The Ruby compiler does NOT refuse it — BabyBear is ported
 * there — so it stays in the Ruby list and is expected to match.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findJavaBinary, findRubyBinary } from '../conformance/runner/runner.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Exactly the source paths integration/java's test classes pass to
// ContractCompiler.compileRelative(), minus the two StateCovenant entries
// (checked separately below — see the file header).
const JAVA_PATHS = [
  'examples/java/src/main/java/runar/examples/auction/Auction.runar.java',
  'examples/java/src/main/java/runar/examples/bitwise-ops/BitwiseOps.runar.java',
  'examples/java/src/main/java/runar/examples/blake3/Blake3Test.runar.java',
  'examples/java/src/main/java/runar/examples/bsv20-token/BSV20Token.runar.java',
  'examples/java/src/main/java/runar/examples/bsv21-token/BSV21Token.runar.java',
  'examples/java/src/main/java/runar/examples/convergence-proof/ConvergenceProof.runar.java',
  'examples/java/src/main/java/runar/examples/covenant-vault/CovenantVault.runar.java',
  'examples/java/src/main/java/runar/examples/escrow/Escrow.runar.java',
  'examples/java/src/main/java/runar/examples/function-patterns/FunctionPatterns.runar.java',
  'examples/java/src/main/java/runar/examples/math-demo/MathDemo.runar.java',
  'examples/java/src/main/java/runar/examples/message-board/MessageBoard.runar.java',
  'examples/java/src/main/java/runar/examples/oracle-price/OraclePriceFeed.runar.java',
  'examples/java/src/main/java/runar/examples/ordinal-nft/OrdinalNFT.runar.java',
  'examples/java/src/main/java/runar/examples/p256-wallet/P256Wallet.runar.java',
  'examples/java/src/main/java/runar/examples/p2pkh/P2PKH.runar.java',
  'examples/java/src/main/java/runar/examples/p384-wallet/P384Wallet.runar.java',
  'examples/java/src/main/java/runar/examples/post-quantum-wallet/PostQuantumWallet.runar.java',
  'examples/java/src/main/java/runar/examples/schnorr-zkp/SchnorrZKP.runar.java',
  'examples/java/src/main/java/runar/examples/sha256-compress/Sha256CompressTest.runar.java',
  'examples/java/src/main/java/runar/examples/sha256-finalize/Sha256FinalizeTest.runar.java',
  'examples/java/src/main/java/runar/examples/sphincs-wallet/SPHINCSWallet.runar.java',
  'examples/java/src/main/java/runar/examples/stateful-counter/Counter.runar.java',
  'examples/java/src/main/java/runar/examples/tic-tac-toe/TicTacToe.runar.java',
  'examples/java/src/main/java/runar/examples/token-ft/FungibleTokenExample.runar.java',
  'examples/java/src/main/java/runar/examples/token-nft/NFTExample.runar.java',
  'examples/ts/auction/Auction.runar.ts',
  'examples/ts/blake3/Blake3Test.runar.ts',
  'examples/ts/bsv20-token/BSV20Token.runar.ts',
  'examples/ts/bsv21-token/BSV21Token.runar.ts',
  'examples/ts/convergence-proof/ConvergenceProof.runar.ts',
  'examples/ts/covenant-vault/CovenantVault.runar.ts',
  'examples/ts/escrow/Escrow.runar.ts',
  'examples/ts/function-patterns/FunctionPatterns.runar.ts',
  'examples/ts/math-demo/MathDemo.runar.ts',
  'examples/ts/message-board/MessageBoard.runar.ts',
  'examples/ts/oracle-price/OraclePriceFeed.runar.ts',
  'examples/ts/ordinal-nft/OrdinalNFT.runar.ts',
  'examples/ts/p256-wallet/P256Wallet.runar.ts',
  'examples/ts/p2pkh/P2PKH.runar.ts',
  'examples/ts/p384-wallet/P384Wallet.runar.ts',
  'examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts',
  'examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts',
  'examples/ts/schnorr-zkp/SchnorrZKP.runar.ts',
  'examples/ts/sha256-compress/Sha256CompressTest.runar.ts',
  'examples/ts/sha256-finalize/Sha256FinalizeTest.runar.ts',
  'examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts',
  'examples/ts/stateful-counter/Counter.runar.ts',
  'examples/ts/tic-tac-toe/TicTacToe.runar.ts',
  'examples/ts/token-ft/FungibleTokenExample.runar.ts',
  'examples/ts/token-nft/NFTExample.runar.ts',
  'integration/contracts/constructs/BranchMergedLocals.runar.ts',
  'integration/contracts/constructs/ConditionalDataOutput.runar.ts',
  'integration/contracts/constructs/CondWriteMultiField.runar.ts',
  'integration/contracts/constructs/StateByteString1B.runar.ts',
  'integration/contracts/crypto/MultiSig2of3.runar.ts',
  'integration/contracts/outputs/RawOutput.runar.ts',
];

// The documented exception (ContractCompiler.TS_REFERENCE_ONLY): Java
// refuses both because they call the BabyBear builtin `bbFieldMul`.
const JAVA_REFUSES = [
  'examples/java/src/main/java/runar/examples/state-covenant/StateCovenant.runar.java',
  'examples/ts/state-covenant/StateCovenant.runar.ts',
];

// Exactly the source paths integration/ruby's specs pass to
// compile_contract(). No exceptions: the Ruby compiler ports BabyBear, so
// StateCovenant compiles (and matches) there.
const RUBY_PATHS = [
  'examples/ts/auction/Auction.runar.ts',
  'examples/ts/bsv20-token/BSV20Token.runar.ts',
  'examples/ts/bsv21-token/BSV21Token.runar.ts',
  'examples/ts/convergence-proof/ConvergenceProof.runar.ts',
  'examples/ts/covenant-vault/CovenantVault.runar.ts',
  'examples/ts/escrow/Escrow.runar.ts',
  'examples/ts/function-patterns/FunctionPatterns.runar.ts',
  'examples/ts/math-demo/MathDemo.runar.ts',
  'examples/ts/message-board/MessageBoard.runar.ts',
  'examples/ts/oracle-price/OraclePriceFeed.runar.ts',
  'examples/ts/ordinal-nft/OrdinalNFT.runar.ts',
  'examples/ts/p256-wallet/P256Wallet.runar.ts',
  'examples/ts/p2pkh/P2PKH.runar.ts',
  'examples/ts/p384-wallet/P384Wallet.runar.ts',
  'examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts',
  'examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts',
  'examples/ts/schnorr-zkp/SchnorrZKP.runar.ts',
  'examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts',
  'examples/ts/state-covenant/StateCovenant.runar.ts',
  'examples/ts/stateful-counter/Counter.runar.ts',
  'examples/ts/tic-tac-toe/TicTacToe.runar.ts',
  'examples/ts/token-ft/FungibleTokenExample.runar.ts',
  'examples/ts/token-nft/NFTExample.runar.ts',
  'integration/contracts/constructs/BranchMergedLocals.runar.ts',
  'integration/contracts/constructs/CondWriteMultiField.runar.ts',
  'integration/contracts/constructs/ConditionalDataOutput.runar.ts',
  'integration/contracts/constructs/StateByteString1B.runar.ts',
  'integration/contracts/outputs/RawOutput.runar.ts',
  'integration/contracts/crypto/MultiSig2of3.runar.ts',
];

function splitCmd(s: string): { cmd: string; args: string[] } {
  const parts = s.trim().split(/\s+/);
  return { cmd: parts[0], args: parts.slice(1) };
}

/** The TS reference compiler's script hex, in-process, fold-ON (the default). */
async function tsScriptHex(relPath: string): Promise<string> {
  const { compile } = await import('runar-compiler');
  const src = readFileSync(join(ROOT, relPath), 'utf-8');
  const r = compile(src, { fileName: relPath.split('/').pop()! });
  if (!r.success) {
    throw new Error(`TS compile failed for ${relPath}:\n${r.diagnostics.map((d) => d.message).join('\n')}`);
  }
  return r.artifact!.script;
}

const javaBinary = findJavaBinary();
const rubyBinary = findRubyBinary();

describe('F-276: native-compiler script hex matches the TS reference (offline)', () => {
  it('at least one of the two switched tiers (java, ruby) is built — a zero-tier run proves nothing', () => {
    expect([javaBinary, rubyBinary].filter((b) => b !== null).length).toBeGreaterThanOrEqual(1);
  });

  describe.skipIf(javaBinary === null)('java', () => {
    for (const relPath of JAVA_PATHS) {
      it(`${relPath} matches`, async () => {
        const expected = await tsScriptHex(relPath);
        const dir = mkdtempSync(join(tmpdir(), 'f276-java-'));
        const artPath = join(dir, 'artifact.json');
        const { cmd, args } = splitCmd(javaBinary!);
        const res = spawnSync(cmd, [...args, '--source', join(ROOT, relPath), '--emit-artifact', artPath], {
          cwd: join(ROOT, 'compilers/java'),
          encoding: 'utf-8',
          timeout: 300_000,
          maxBuffer: 64 * 1024 * 1024,
        });
        expect(res.status, `java failed: ${(res.stderr ?? '').slice(0, 400)}`).toBe(0);
        const artifact = JSON.parse(readFileSync(artPath, 'utf-8')) as { script: string };
        rmSync(dir, { recursive: true, force: true });
        expect(artifact.script).toEqual(expected);
      });
    }

    for (const relPath of JAVA_REFUSES) {
      it(`${relPath} is a named, documented refusal (BabyBear is Go-only in the Java tier)`, () => {
        const dir = mkdtempSync(join(tmpdir(), 'f276-java-refuse-'));
        const artPath = join(dir, 'artifact.json');
        const { cmd, args } = splitCmd(javaBinary!);
        const res = spawnSync(cmd, [...args, '--source', join(ROOT, relPath), '--emit-artifact', artPath], {
          cwd: join(ROOT, 'compilers/java'),
          encoding: 'utf-8',
          timeout: 300_000,
        });
        rmSync(dir, { recursive: true, force: true });
        expect(res.status).not.toBe(0);
        expect(res.stdout + res.stderr).toContain('BabyBear');
      });
    }
  });

  describe.skipIf(rubyBinary === null)('ruby', () => {
    for (const relPath of RUBY_PATHS) {
      it(`${relPath} matches`, async () => {
        const expected = await tsScriptHex(relPath);
        const { cmd, args } = splitCmd(rubyBinary!);
        const res = spawnSync(cmd, [...args, '--source', join(ROOT, relPath)], {
          cwd: join(ROOT, 'compilers/ruby'),
          encoding: 'utf-8',
          timeout: 300_000,
          maxBuffer: 64 * 1024 * 1024,
        });
        expect(res.status, `ruby failed: ${(res.stderr ?? '').slice(0, 400)}`).toBe(0);
        const artifact = JSON.parse(res.stdout) as { script: string };
        expect(artifact.script).toEqual(expected);
      });
    }
  });
});
