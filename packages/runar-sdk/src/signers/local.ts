// ---------------------------------------------------------------------------
// runar-sdk/signers/local.ts — Local signer (private key in memory)
// ---------------------------------------------------------------------------
//
// Uses @bsv/sdk for real secp256k1 key derivation, address generation,
// and ECDSA signing with BIP-143 sighash preimage computation.
// ---------------------------------------------------------------------------

import type { Signer } from './signer.js';
import { PrivateKey, TransactionSignature, Hash } from '@bsv/sdk';

/** SIGHASH_ALL | SIGHASH_FORKID — the default BSV sighash type. */
const SIGHASH_ALL_FORKID = 0x41;

/**
 * Local (in-process) signer that holds a private key in memory.
 *
 * Suitable for CLI tooling and testing. Not recommended for production
 * wallets — use ExternalSigner with hardware wallet callbacks instead.
 */
export class LocalSigner implements Signer {
  private readonly bsvPrivKey: PrivateKey;
  private readonly privateKeyHex: string;

  constructor(privateKeyHex: string) {
    if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
      throw new Error(
        'LocalSigner: expected a 32-byte hex-encoded private key (64 hex chars)',
      );
    }
    this.privateKeyHex = privateKeyHex;
    this.bsvPrivKey = PrivateKey.fromHex(privateKeyHex);
  }

  async getPublicKey(): Promise<string> {
    // Derive compressed public key via secp256k1 point multiplication.
    const pubKey = this.bsvPrivKey.toPublicKey();
    return pubKey.toDER('hex') as string;
  }

  async getAddress(): Promise<string> {
    // Bitcoin address = Base58Check( 0x00 + HASH160(pubkey) )
    return this.bsvPrivKey.toAddress();
  }

  /** Get the raw private key hex (for integration with @bsv/sdk). */
  getPrivateKeyHex(): string {
    return this.privateKeyHex;
  }

  async sign(
    txHex: string,
    inputIndex: number,
    subscript: string,
    satoshis: number,
    sigHashType: number = SIGHASH_ALL_FORKID,
  ): Promise<string> {
    const scope = sigHashType;

    // Compute BIP-143 sighash preimage and sign with ECDSA.
    //
    // We parse the raw transaction hex to extract the fields needed by
    // TransactionSignature.format(). This gives us a proper sighash digest
    // which we then sign with the private key.
    const txBytes = hexToBytes(txHex);
    const parsed = parseRawTx(txBytes);

    const otherInputs = parsed.inputs
      .filter((_inp, i) => i !== inputIndex)
      .map((inp) => ({
        sourceTXID: inp.prevTxid,
        sourceOutputIndex: inp.prevOutputIndex,
        sequence: inp.sequence,
      }));

    const outputs = parsed.outputs.map((out) => ({
      satoshis: out.satoshis,
      lockingScript: scriptShimFromHex(out.scriptHex),
    }));

    const preimage = TransactionSignature.format({
      sourceTXID: parsed.inputs[inputIndex]!.prevTxid,
      sourceOutputIndex: parsed.inputs[inputIndex]!.prevOutputIndex,
      sourceSatoshis: satoshis,
      transactionVersion: parsed.version,
      otherInputs: otherInputs as Parameters<typeof TransactionSignature.format>[0]['otherInputs'],
      outputs: outputs as unknown as Parameters<typeof TransactionSignature.format>[0]['outputs'],
      inputIndex,
      subscript: scriptShimFromHex(subscript) as unknown as Parameters<typeof TransactionSignature.format>[0]['subscript'],
      inputSequence: parsed.inputs[inputIndex]!.sequence,
      lockTime: parsed.locktime,
      scope,
    });

    // PrivateKey.sign() internally SHA-256 hashes its input before signing.
    // We pass SHA256(preimage) so the total is SHA256(SHA256(preimage)) =
    // hash256(preimage), which is the correct BIP-143 sighash digest.
    const sighash = Hash.sha256(preimage);
    const signature = this.bsvPrivKey.sign(sighash);

    // Return DER-encoded signature with sighash byte appended
    const derHex = signature.toDER('hex') as string;
    return derHex + toHexByte(scope);
  }
}

// ---------------------------------------------------------------------------
// Minimal raw transaction parser
// ---------------------------------------------------------------------------

interface ParsedInput {
  prevTxid: string;
  prevOutputIndex: number;
  scriptHex: string;
  sequence: number;
}

interface ParsedOutput {
  satoshis: number;
  scriptHex: string;
}

interface ParsedTx {
  version: number;
  inputs: ParsedInput[];
  outputs: ParsedOutput[];
  locktime: number;
}

function parseRawTx(bytes: Uint8Array): ParsedTx {
  let offset = 0;

  function read(n: number): Uint8Array {
    const slice = bytes.slice(offset, offset + n);
    offset += n;
    return slice;
  }

  function readUint32LE(): number {
    const b = read(4);
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;
  }

  function readUint64LE(): number {
    const lo = readUint32LE();
    const hi = readUint32LE();
    return lo + hi * 0x100000000;
  }

  function readVarInt(): number {
    const first = read(1)[0]!;
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const b = read(2);
      return b[0]! | (b[1]! << 8);
    }
    if (first === 0xfe) {
      return readUint32LE();
    }
    // 0xff
    return readUint32LE() + readUint32LE() * 0x100000000;
  }

  const version = readUint32LE();

  const inputCount = readVarInt();
  const inputs: ParsedInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    // Previous txid is stored in internal byte order (reversed)
    const prevTxidBytes = read(32);
    const prevTxid = reverseBytes(prevTxidBytes);
    const prevOutputIndex = readUint32LE();
    const scriptLen = readVarInt();
    const scriptBytes = read(scriptLen);
    const scriptHex = bytesToHex(scriptBytes);
    const sequence = readUint32LE();
    inputs.push({ prevTxid, prevOutputIndex, scriptHex, sequence });
  }

  const outputCount = readVarInt();
  const outputs: ParsedOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    const satoshis = readUint64LE();
    const scriptLen = readVarInt();
    const scriptBytes = read(scriptLen);
    const scriptHex = bytesToHex(scriptBytes);
    outputs.push({ satoshis, scriptHex });
  }

  const locktime = readUint32LE();

  return { version, inputs, outputs, locktime };
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function reverseBytes(bytes: Uint8Array): string {
  return Array.from(bytes)
    .reverse()
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toHexByte(n: number): string {
  return n.toString(16).padStart(2, '0');
}

/**
 * Create a minimal script-like shim from hex, compatible with the subset of
 * the Script interface used by TransactionSignature.format() in BIP-143 mode.
 *
 * BIP-143 path accesses: .toUint8Array()
 * OTDA path accesses: .chunks, .toBinary()
 */
function scriptShimFromHex(hex: string): {
  toBinary: () => number[];
  toUint8Array: () => Uint8Array;
  toHex: () => string;
  chunks: never[];
} {
  const binary = Array.from(hexToBytes(hex));
  const uint8 = hexToBytes(hex);
  return {
    toBinary: () => binary,
    toUint8Array: () => uint8,
    toHex: () => hex,
    chunks: [] as never[],
  };
}
