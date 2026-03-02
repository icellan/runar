// ---------------------------------------------------------------------------
// runar-cli/commands/verify.ts — Verify a deployed contract
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';
import { WhatsOnChainProvider } from 'runar-sdk';
import type { RunarArtifact } from 'runar-sdk';

interface VerifyCommandOptions {
  artifact: string;
  network: string;
}

/**
 * Verify that a deployed transaction's locking script matches a compiled
 * artifact.
 *
 * Fetches the transaction from the blockchain and compares its first
 * output's locking script with the script in the artifact. Reports whether
 * they match.
 */
export async function verifyCommand(
  txid: string,
  options: VerifyCommandOptions,
): Promise<void> {
  // Validate network
  const network = options.network as 'mainnet' | 'testnet';
  if (network !== 'mainnet' && network !== 'testnet') {
    console.error(`Invalid network: ${options.network}. Use 'mainnet' or 'testnet'.`);
    process.exitCode = 1;
    return;
  }

  // Load artifact
  const artifactPath = path.resolve(process.cwd(), options.artifact);
  let artifact: RunarArtifact;
  try {
    const raw = fs.readFileSync(artifactPath, 'utf-8');
    artifact = JSON.parse(raw) as RunarArtifact;
  } catch (err) {
    console.error(`Failed to load artifact: ${(err as Error).message}`);
    process.exitCode = 1;
    return;
  }

  console.log(`Verifying contract: ${artifact.contractName}`);
  console.log(`  TXID: ${txid}`);
  console.log(`  Network: ${network}`);
  console.log('');

  // Fetch the transaction
  const provider = new WhatsOnChainProvider(network);

  let onChainScript: string;
  try {
    const tx = await provider.getTransaction(txid);

    if (tx.outputs.length === 0) {
      console.error('Transaction has no outputs.');
      process.exitCode = 1;
      return;
    }

    // The contract output is expected to be at index 0
    onChainScript = tx.outputs[0]!.script;

    console.log(`  On-chain script (output 0): ${truncateHex(onChainScript)}`);
    console.log(`  Artifact script:            ${truncateHex(artifact.script)}`);
    console.log('');
  } catch (err) {
    console.error(`Failed to fetch transaction: ${(err as Error).message}`);
    process.exitCode = 1;
    return;
  }

  // Compare scripts
  // For non-stateful contracts, the scripts should match exactly.
  // For stateful contracts, the code prefix should match (state suffix may differ).
  const exactMatch = onChainScript === artifact.script;
  const prefixMatch = onChainScript.startsWith(artifact.script);

  if (exactMatch) {
    console.log('Verification result: MATCH');
    console.log('  The on-chain locking script exactly matches the artifact.');
  } else if (prefixMatch) {
    console.log('Verification result: PARTIAL MATCH (stateful)');
    console.log(
      '  The on-chain script starts with the artifact script. The remaining',
    );
    console.log(
      '  bytes are likely constructor parameters and/or state data.',
    );

    // Try to extract state if the artifact defines state fields
    if (artifact.stateFields && artifact.stateFields.length > 0) {
      console.log('');
      console.log('  State fields detected. Contract appears to be stateful.');
      console.log(`  State field count: ${artifact.stateFields.length}`);
      for (const field of artifact.stateFields) {
        console.log(`    [${field.index}] ${field.name}: ${field.type}`);
      }
    }
  } else {
    console.log('Verification result: MISMATCH');
    console.log('  The on-chain locking script does NOT match the artifact.');
    console.log('');

    // Show where the scripts first diverge
    const divergeIndex = findDivergenceIndex(onChainScript, artifact.script);
    console.log(`  First divergence at hex offset: ${divergeIndex}`);
    if (divergeIndex < onChainScript.length && divergeIndex < artifact.script.length) {
      console.log(
        `    On-chain: ...${onChainScript.slice(Math.max(0, divergeIndex - 8), divergeIndex + 16)}...`,
      );
      console.log(
        `    Artifact: ...${artifact.script.slice(Math.max(0, divergeIndex - 8), divergeIndex + 16)}...`,
      );
    }

    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncateHex(hex: string, maxLen: number = 60): string {
  if (hex.length <= maxLen) return hex;
  return hex.slice(0, maxLen / 2) + '...' + hex.slice(-maxLen / 2);
}

function findDivergenceIndex(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return i;
  }
  return len;
}
