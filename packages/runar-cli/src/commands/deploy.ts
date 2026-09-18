// ---------------------------------------------------------------------------
// runar-cli/commands/deploy.ts — Deploy a compiled contract
// ---------------------------------------------------------------------------

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import {
  RunarContract,
  WhatsOnChainProvider,
  LocalSigner,
} from 'runar-sdk';
import type { RunarArtifact } from 'runar-sdk';
import { abiValueEncoding } from 'runar-ir-schema';

interface DeployCommandOptions {
  network: string;
  key: string;
  satoshis: string;
  /**
   * Constructor argument values, in `abi.constructor.params` order, as raw
   * CLI strings. Parsed by `parseConstructorArgs` and spliced into the
   * template's `constructorSlots` by the SDK.
   */
  args?: string[];
}

// ---------------------------------------------------------------------------
// Constructor argument parsing
// ---------------------------------------------------------------------------


/**
 * Parse `--args` values into the positional constructor argument list that
 * `RunarContract` splices into `artifact.constructorSlots`.
 *
 * Parsing is type-directed: integers are decimal, byte strings are hex
 * (optionally `0x`-prefixed), booleans are `true`/`false`. A value that does
 * not match its parameter's type is rejected rather than coerced — a coerced
 * constructor arg bakes the wrong value into a locking script, and the funds
 * sent to that script are not recoverable.
 *
 * Omitting `--args` for a contract whose constructor declares parameters is an
 * error. It used to zero-fill, which silently produced e.g. the P2PKH script
 * `OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG` — an output nobody can
 * ever spend.
 *
 * @throws Error with a human-readable message on any arity or type mismatch.
 */
export function parseConstructorArgs(
  artifact: RunarArtifact,
  rawArgs: string[] | undefined,
): unknown[] {
  const params = artifact.abi.constructor.params;

  if (params.length === 0) {
    if (rawArgs && rawArgs.length > 0) {
      throw new Error(
        `${artifact.contractName} has a zero-parameter constructor, but ${rawArgs.length} --args value(s) were supplied`,
      );
    }
    return [];
  }

  if (!rawArgs || rawArgs.length === 0) {
    throw new Error(
      `${artifact.contractName} expects ${params.length} constructor argument(s) ` +
        `(${params.map((p) => `${p.name}: ${p.type}`).join(', ')}), but none were supplied. ` +
        `Pass them with --args. Deploying without them would bake zeros into the ` +
        `locking script and lock the funds to a script nobody can spend.`,
    );
  }

  if (rawArgs.length !== params.length) {
    throw new Error(
      `${artifact.contractName} expects ${params.length} constructor argument(s), got ${rawArgs.length}`,
    );
  }

  // Index the enriched slot descriptors by paramIndex — they carry the
  // authoritative encoding and fixed byte width when the artifact has them.
  type Slot = NonNullable<RunarArtifact['constructorSlots']>[number];
  const slotByParam = new Map<number, Slot>();
  for (const slot of artifact.constructorSlots ?? []) {
    slotByParam.set(slot.paramIndex, slot);
  }

  return params.map((param, i) => {
    const raw = rawArgs[i]!;
    const slot = slotByParam.get(i);
    const label = `constructor arg ${i} (${param.name}: ${param.type})`;

    if (param.fixedArray) {
      throw new Error(
        `${label} is a FixedArray<${param.fixedArray.elementType}, ${param.fixedArray.length}>, ` +
          `which --args cannot express. Deploy this contract through the SDK.`,
      );
    }

    // The ABI type is authoritative — NOT the artifact's slot descriptor. An
    // artifact compiled before the `RabinSig`/`RabinPubKey` classification was
    // fixed says `'data'` for a slot the script consumes with OP_MOD; trusting
    // that descriptor is exactly how a byte-reversed modulus got baked into a
    // locking script. A descriptor that contradicts its own type is a stale
    // artifact, and the only safe response is to refuse the deploy.
    const encoding = abiValueEncoding(param.type);
    if (slot?.valueEncoding !== undefined && slot.valueEncoding !== encoding) {
      throw new Error(
        `${label}: the artifact records valueEncoding '${slot.valueEncoding}' but the ` +
          `ABI type '${param.type}' is encoded as '${encoding}'. This artifact predates ` +
          `the slot-encoding fix — recompile it before deploying. Deploying on the stale ` +
          `descriptor would bake a wrongly-encoded value into the locking script.`,
      );
    }

    switch (encoding) {
      case 'scriptnum': {
        // Decimal, or an explicit `0x`-prefixed BIG-ENDIAN integer literal.
        // A BARE hex string is refused on purpose: `12345678901234567890` is
        // simultaneously a valid decimal and a valid hex byte string, so
        // accepting it means guessing which the operator meant — and the
        // wrong guess bakes a different number into the script. Script reads
        // this slot little-endian; `encodeArg` does that conversion from the
        // bigint, so the operator never types byte order.
        const hexInt = /^(-?)0[xX]([0-9a-fA-F]+)$/.exec(raw);
        // `BigInt('-0x…')` throws — the sign has to come off the literal.
        if (hexInt) return (hexInt[1] === '-' ? -1n : 1n) * BigInt(`0x${hexInt[2]}`);
        if (!/^-?(0|[1-9][0-9]*)$/.test(raw)) {
          throw new Error(
            `${label} must be a decimal integer (or an explicit 0x-prefixed ` +
              `big-endian hex integer), got '${raw}'`,
          );
        }
        return BigInt(raw);
      }
      case 'bool': {
        if (raw !== 'true' && raw !== 'false') {
          throw new Error(`${label} must be 'true' or 'false', got '${raw}'`);
        }
        return raw === 'true';
      }
      case 'data': {
        const hex = (raw.startsWith('0x') || raw.startsWith('0X')
          ? raw.slice(2)
          : raw
        ).toLowerCase();
        if (!/^[0-9a-f]*$/.test(hex)) {
          throw new Error(
            `${label} must be a hex byte string, got '${raw}'`,
          );
        }
        if (hex.length % 2 !== 0) {
          throw new Error(
            `${label} must be a hex byte string with an even number of digits, got ${hex.length} digits`,
          );
        }
        const expected = slot?.fixedValueByteLength;
        if (expected !== undefined && hex.length / 2 !== expected) {
          throw new Error(
            `${label} expects ${expected} bytes, got ${hex.length / 2}`,
          );
        }
        return hex;
      }
    }
  });
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

  // Resolve constructor args BEFORE touching keys or the network. These are
  // baked into the locking script at `artifact.constructorSlots`, so getting
  // them wrong (or defaulting them to zero) burns the deployed satoshis.
  let constructorArgs: unknown[];
  try {
    constructorArgs = parseConstructorArgs(artifact, options.args);
  } catch (err) {
    console.error(`Invalid constructor arguments: ${(err as Error).message}`);
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
 *
 * The trailing 4-byte checksum is `SHA256(SHA256(payload))[0..4]` where
 * `payload` is everything before the checksum. We must verify it so a WIF
 * corrupted in transit is rejected rather than silently producing a
 * different private key.
 */
export function decodeWIF(wif: string): string {
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

  // Verify the Base58Check checksum before trusting any of the payload.
  const payloadHex = hex.slice(0, (totalBytes - 4) * 2);
  const checksumHex = hex.slice((totalBytes - 4) * 2);
  const payloadBytes = Buffer.from(payloadHex, 'hex');
  const firstHash = createHash('sha256').update(payloadBytes).digest();
  const secondHash = createHash('sha256').update(firstHash).digest();
  const expectedChecksum = secondHash.subarray(0, 4).toString('hex');
  if (expectedChecksum !== checksumHex) {
    throw new Error(
      `Invalid WIF checksum: expected ${expectedChecksum}, got ${checksumHex}`,
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
