/**
 * Wallet helper — creates funded wallets for integration tests.
 *
 * Uses deterministic sequential keys for reproducibility. Each call to
 * createWallet() returns a unique key derived from an incrementing
 * private key number, avoiding RNG dependency and UTXO conflicts.
 */

import { PrivateKey, Hash } from '@bsv/sdk';
import { LocalSigner, ExternalSigner, RPCProvider } from 'runar-sdk';
import type { Signer } from 'runar-sdk';
import { fundAddress, rpcCall } from './node.js';
import { createHash } from 'crypto';

export interface TestWallet {
  privKeyHex: string;
  pubKeyHex: string;
  pubKeyHash: string;
  address: string; // regtest address
  signer: Signer;
}

/**
 * Counter for generating unique deterministic keys.
 * Seeded from process.pid to avoid collisions between parallel vitest
 * workers. Each worker has a unique PID, so keys don't overlap.
 */
let walletIndex = (process.pid ?? 1) * 1000;

/**
 * Create a deterministic wallet from a sequential private key number.
 * Each call returns a unique key (counter never wraps within a test run).
 */
export function createWallet(): { privKeyHex: string; pubKeyHex: string; pubKeyHash: string } {
  walletIndex++;
  const privHex = walletIndex.toString(16).padStart(64, '0');
  const privKey = new PrivateKey(privHex, 16);
  const pubKey = privKey.toPublicKey();
  const pubKeyDer = pubKey.toDER('hex') as string;

  // Compute hash160 manually: RIPEMD160(SHA256(pubkey_bytes))
  const sha = createHash('sha256').update(Buffer.from(pubKeyDer, 'hex')).digest();
  const hash160 = createHash('ripemd160').update(sha).digest('hex');

  return {
    privKeyHex: privKey.toHex(),
    pubKeyHex: pubKeyDer,
    pubKeyHash: hash160,
  };
}

/**
 * Derive regtest address from pubKeyHash.
 * Regtest uses version byte 0x6f (111).
 */
function regtestAddress(pubKeyHash: string): string {
  const versionByte = Buffer.from([0x6f]);
  const payload = Buffer.concat([versionByte, Buffer.from(pubKeyHash, 'hex')]);
  // Base58Check: payload + first 4 bytes of SHA256(SHA256(payload))
  const hash1 = createHash('sha256').update(payload).digest();
  const hash2 = createHash('sha256').update(hash1).digest();
  const checksum = hash2.subarray(0, 4);
  const full = Buffer.concat([payload, checksum]);
  return base58Encode(full);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buffer: Buffer): string {
  let num = BigInt('0x' + buffer.toString('hex'));
  let result = '';
  while (num > 0n) {
    const [div, mod] = [num / 58n, num % 58n];
    result = BASE58_ALPHABET[Number(mod)] + result;
    num = div;
  }
  // Leading zeros
  for (const byte of buffer) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result;
}

/**
 * Create a funded test wallet with an SDK-compatible signer.
 */
export async function createFundedWallet(
  provider: RPCProvider,
  btcAmount: number = 1.0,
): Promise<TestWallet> {
  const { privKeyHex, pubKeyHex, pubKeyHash } = createWallet();
  const address = regtestAddress(pubKeyHash);

  // Import address so listunspent can find UTXOs
  await rpcCall('importaddress', address, '', false);
  await fundAddress(address, btcAmount);

  // Create a signer that returns the regtest address
  const localSigner = new LocalSigner(privKeyHex);

  const signer = new ExternalSigner(
    pubKeyHex,
    address,
    async (txHex: string, inputIndex: number, subscript: string, satoshis: number, sigHashType?: number) => {
      return localSigner.sign(txHex, inputIndex, subscript, satoshis, sigHashType ?? 0x41);
    },
  );

  return { privKeyHex, pubKeyHex, pubKeyHash, address, signer };
}
