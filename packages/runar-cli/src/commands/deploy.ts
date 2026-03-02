// ---------------------------------------------------------------------------
// runar-cli/commands/deploy.ts — Deploy a compiled contract
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  RunarContract,
  WhatsOnChainProvider,
  LocalSigner,
} from 'runar-sdk';
import type { RunarArtifact } from 'runar-sdk';

interface DeployCommandOptions {
  network: string;
  key: string;
  satoshis: string;
}

/**
 * Deploy a compiled Rúnar contract to the BSV blockchain.
 *
 * Reads the artifact JSON, creates a provider and signer, deploys the
 * contract, and prints the resulting transaction ID.
 */
export async function deployCommand(
  artifactPath: string,
  options: DeployCommandOptions,
): Promise<void> {
  // Validate network
  const network = options.network as 'mainnet' | 'testnet';
  if (network !== 'mainnet' && network !== 'testnet') {
    console.error(`Invalid network: ${options.network}. Use 'mainnet' or 'testnet'.`);
    process.exitCode = 1;
    return;
  }

  // Load artifact
  const resolvedPath = path.resolve(process.cwd(), artifactPath);
  let artifact: RunarArtifact;
  try {
    const raw = fs.readFileSync(resolvedPath, 'utf-8');
    artifact = JSON.parse(raw) as RunarArtifact;
  } catch (err) {
    console.error(`Failed to load artifact: ${(err as Error).message}`);
    process.exitCode = 1;
    return;
  }

  console.log(`Deploying contract: ${artifact.contractName}`);
  console.log(`  Network: ${network}`);
  console.log(`  Satoshis: ${options.satoshis}`);

  // Decode the private key.
  // The --key flag accepts a WIF-encoded private key. We need to decode
  // it to raw hex for the LocalSigner.
  let privateKeyHex: string;
  try {
    privateKeyHex = decodeWIF(options.key);
  } catch (err) {
    console.error(`Invalid private key: ${(err as Error).message}`);
    process.exitCode = 1;
    return;
  }

  // Create provider and signer
  const provider = new WhatsOnChainProvider(network);
  const signer = new LocalSigner(privateKeyHex);

  const satoshis = parseInt(options.satoshis, 10);
  if (isNaN(satoshis) || satoshis <= 0) {
    console.error(`Invalid satoshis value: ${options.satoshis}`);
    process.exitCode = 1;
    return;
  }

  // Create contract instance with empty constructor args
  // (the script from the artifact already has constructor params baked in)
  const constructorArgs = new Array(artifact.abi.constructor.params.length).fill(
    0n,
  ) as unknown[];
  const contract = new RunarContract(artifact, constructorArgs);

  try {
    const address = await signer.getAddress();
    console.log(`  Deployer address: ${address}`);
    console.log('');
    console.log('Broadcasting...');

    const { txid } = await contract.deploy(provider, signer, { satoshis });

    console.log('');
    console.log('Deployment successful!');
    console.log(`  TXID: ${txid}`);
    console.log(
      `  Explorer: https://whatsonchain.com/tx/${txid}`,
    );
  } catch (err) {
    console.error(`Deployment failed: ${(err as Error).message}`);
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// WIF decoding
// ---------------------------------------------------------------------------

/**
 * Decode a WIF (Wallet Import Format) private key to raw hex.
 *
 * WIF format: Base58Check( version_byte + private_key + [compressed_flag] + checksum )
 * - Mainnet version byte: 0x80
 * - Testnet version byte: 0xef
 * - Compressed flag: 0x01 (optional, indicates compressed pubkey)
 */
function decodeWIF(wif: string): string {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  // Base58 decode
  let num = 0n;
  for (const char of wif) {
    const idx = ALPHABET.indexOf(char);
    if (idx === -1) {
      throw new Error(`Invalid Base58 character: ${char}`);
    }
    num = num * 58n + BigInt(idx);
  }

  // Convert to bytes
  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;

  // Add leading zero bytes for leading '1' characters in Base58
  let leadingOnes = 0;
  for (const char of wif) {
    if (char !== '1') break;
    leadingOnes++;
  }
  hex = '00'.repeat(leadingOnes) + hex;

  // Validate: should be version(1) + key(32) + [compressed(1)] + checksum(4)
  const totalBytes = hex.length / 2;
  if (totalBytes !== 37 && totalBytes !== 38) {
    throw new Error(
      `Invalid WIF length: expected 37 or 38 bytes, got ${totalBytes}`,
    );
  }

  // Extract private key (skip version byte, strip checksum and optional compressed flag)
  const versionByte = hex.slice(0, 2);
  if (versionByte !== '80' && versionByte !== 'ef') {
    throw new Error(`Invalid WIF version byte: 0x${versionByte}`);
  }

  // If compressed (38 bytes total), key is bytes 1-32, compressed flag is byte 33
  // If uncompressed (37 bytes), key is bytes 1-32
  const privateKeyHex = hex.slice(2, 66); // 32 bytes = 64 hex chars

  if (privateKeyHex.length !== 64) {
    throw new Error('Failed to extract 32-byte private key from WIF');
  }

  return privateKeyHex;
}
