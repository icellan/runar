/**
 * mock-preimage.ts — Standalone helpers for building mock BIP-143 preimages
 * for stateful Runar contracts.
 *
 * Designed for applications like the Runar Playground that need to execute
 * compiled contracts without real Bitcoin transactions.
 *
 * Uses @bsv/sdk (already a dependency of runar-testing) for ECDSA signing and
 * hashing.
 */

import type {
  RunarArtifact,
  StateField,
} from 'runar-ir-schema';
import {
  PrivateKey,
  Hash,
  BigNumber,
} from '@bsv/sdk';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StatefulPreimageParams {
  /** The compiled artifact */
  artifact: RunarArtifact;
  /** Constructor arguments (used to build the code part of the locking script) */
  constructorArgs: Record<string, bigint | boolean | string>;
  /** Current state values (the state that's in the UTXO being spent) */
  state: Record<string, bigint | boolean | string>;
  /** Which public method is being called (index into artifact.abi.methods filtered to public only) */
  methodIndex?: number;
  /** Satoshis in the UTXO being spent (default: 10000) */
  satoshis?: bigint;
  /** For state-mutating methods: the new state after the method executes */
  newState?: Record<string, bigint | boolean | string>;
  /** For state-mutating methods: satoshis in the continuation output (default: same as input) */
  outputSatoshis?: bigint;
  /** Additional raw outputs (hex-encoded, for multi-output methods) */
  additionalOutputs?: string[];
  /** Override BIP-143 fields */
  version?: number;
  locktime?: number;
  sequence?: number;
}

export interface StatefulPreimageResult {
  /** Hex-encoded BIP-143 preimage */
  preimageHex: string;
  /** DER-encoded OP_PUSH_TX signature (with sighash byte) */
  signatureHex: string;
  /** Full locking script (codePart + OP_RETURN + state) */
  lockingScript: string;
  /** Just the code part (without OP_RETURN + state) */
  codePart: string;
  /** The scriptCode used in BIP-143 (post-OP_CODESEPARATOR portion) */
  scriptCode: string;
  /** hashOutputs used in the preimage */
  hashOutputs: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** SIGHASH_ALL | SIGHASH_FORKID */
const SIGHASH_ALL_FORKID = 0x41;

/** secp256k1 curve order N. */
const CURVE_ORDER = new BigNumber(
  'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
  16,
);

/** OP_PUSH_TX private key (k=1). */
const opPushTxPrivKey = PrivateKey.fromHex(
  '0000000000000000000000000000000000000000000000000000000000000001',
);

// ---------------------------------------------------------------------------
// Hex / byte utilities
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array | number[]): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function uint32LE(n: number): string {
  const buf = new Uint8Array(4);
  buf[0] = n & 0xff;
  buf[1] = (n >>> 8) & 0xff;
  buf[2] = (n >>> 16) & 0xff;
  buf[3] = (n >>> 24) & 0xff;
  return bytesToHex(buf);
}

function uint64LE(n: bigint): string {
  const buf = new Uint8Array(8);
  let val = n < 0n ? 0n : n;
  for (let i = 0; i < 8; i++) {
    buf[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytesToHex(buf);
}

// ---------------------------------------------------------------------------
// Hash helpers (using @bsv/sdk)
// ---------------------------------------------------------------------------

function sha256(data: Uint8Array): Uint8Array {
  // Hash.sha256 takes number[] and returns number[]
  const result = Hash.sha256(Array.from(data));
  return new Uint8Array(result);
}

function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

// ---------------------------------------------------------------------------
// State serialization (self-contained, matching runar-sdk/state.ts)
// ---------------------------------------------------------------------------

/**
 * Encode an integer as a fixed-width LE sign-magnitude byte string,
 * matching OP_NUM2BIN behaviour.
 */
function encodeNum2Bin(n: bigint, width: number): string {
  const bytes = new Uint8Array(width);
  const negative = n < 0n;
  let absVal = negative ? -n : n;

  for (let i = 0; i < width && absVal > 0n; i++) {
    bytes[i] = Number(absVal & 0xffn);
    absVal >>= 8n;
  }

  if (negative) {
    bytes[width - 1]! |= 0x80;
  }

  return bytesToHex(bytes);
}

/**
 * Encode variable-length data as Bitcoin Script push data (with length prefix).
 */
function encodePushDataState(dataHex: string): string {
  const len = dataHex.length / 2;
  if (len <= 75) {
    return len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xff) {
    return '4c' + len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xffff) {
    const lo = (len & 0xff).toString(16).padStart(2, '0');
    const hi = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
    return '4d' + lo + hi + dataHex;
  }
  const b0 = (len & 0xff).toString(16).padStart(2, '0');
  const b1 = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
  const b2 = ((len >> 16) & 0xff).toString(16).padStart(2, '0');
  const b3 = ((len >> 24) & 0xff).toString(16).padStart(2, '0');
  return '4e' + b0 + b1 + b2 + b3 + dataHex;
}

function encodeStateValue(value: unknown, type: string): string {
  switch (type) {
    case 'int':
    case 'bigint': {
      let n: bigint;
      if (typeof value === 'bigint') {
        n = value;
      } else if (typeof value === 'string' && value.endsWith('n')) {
        n = BigInt(value.slice(0, -1));
      } else {
        n = BigInt(value as number);
      }
      return encodeNum2Bin(n, 8);
    }
    case 'bool': {
      return value ? '01' : '00';
    }
    case 'PubKey':
    case 'Addr':
    case 'Ripemd160':
    case 'Sha256':
    case 'Point':
      return String(value);
    default: {
      const hex = String(value);
      if (hex.length === 0) return '00';
      return encodePushDataState(hex);
    }
  }
}

/**
 * Serialize state values to hex bytes (no OP_RETURN prefix).
 *
 * Field order is determined by the `index` property of each StateField.
 */
export function serializeState(
  fields: StateField[],
  values: Record<string, unknown>,
): string {
  const sorted = [...fields].sort((a, b) => a.index - b.index);
  let hex = '';
  for (const field of sorted) {
    const value = values[field.name];
    hex += encodeStateValue(value, field.type);
  }
  return hex;
}

// ---------------------------------------------------------------------------
// Varint encoding
// ---------------------------------------------------------------------------

function encodeVarint(n: number): string {
  if (n < 0xfd) return n.toString(16).padStart(2, '0');
  if (n <= 0xffff) {
    return (
      'fd' +
      (n & 0xff).toString(16).padStart(2, '0') +
      ((n >> 8) & 0xff).toString(16).padStart(2, '0')
    );
  }
  if (n <= 0xffffffff) {
    return 'fe' + uint32LE(n);
  }
  throw new Error('Varint too large');
}

// ---------------------------------------------------------------------------
// Constructor arg encoding
// ---------------------------------------------------------------------------

function encodeConstructorArg(value: bigint | boolean | string): string {
  if (typeof value === 'bigint') return encodeNum2Bin(value, 8);
  if (typeof value === 'boolean') return value ? '01' : '00';
  // Hex string for ByteString/PubKey/etc.
  return String(value);
}

// ---------------------------------------------------------------------------
// Code part building
// ---------------------------------------------------------------------------

/**
 * Build the code part of the locking script by substituting constructor args
 * into the artifact's script at the specified byte offsets.
 */
function buildCodePart(
  artifact: RunarArtifact,
  constructorArgs: Record<string, bigint | boolean | string>,
): string {
  let script = artifact.script;
  if (artifact.constructorSlots && artifact.constructorSlots.length > 0) {
    // Sort slots descending by byteOffset to avoid shifting issues
    const slots = [...artifact.constructorSlots].sort(
      (a, b) => b.byteOffset - a.byteOffset,
    );
    for (const slot of slots) {
      const paramName = artifact.abi.constructor.params[slot.paramIndex]?.name;
      if (!paramName) continue;
      const value = constructorArgs[paramName];
      if (value === undefined) continue;
      const encoded = encodeConstructorArg(value);
      const hexOffset = slot.byteOffset * 2;
      // Replace the OP_0 placeholder (2 hex chars) with the encoded value
      script = script.slice(0, hexOffset) + encoded + script.slice(hexOffset + 2);
    }
  }
  return script;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build the locking script for a stateful contract:
 * codePart + OP_RETURN + serialized state.
 */
export function buildLockingScript(
  artifact: RunarArtifact,
  constructorArgs: Record<string, bigint | boolean | string>,
  state: Record<string, bigint | boolean | string>,
): string {
  const codePart = buildCodePart(artifact, constructorArgs);
  const stateFields = artifact.stateFields ?? [];
  if (stateFields.length === 0) {
    return codePart;
  }
  const stateHex = serializeState(stateFields, state);
  // 0x6a = OP_RETURN
  return codePart + '6a' + stateHex;
}

/**
 * Build a continuation output (for state-mutating methods).
 * Returns the serialized output: amount(8-byte LE) + varint(scriptLen) + script
 */
export function buildContinuationOutput(
  codePart: string,
  stateFields: StateField[],
  newState: Record<string, bigint | boolean | string>,
  satoshis: bigint,
): string {
  const stateHex = serializeState(stateFields, newState);
  const script = codePart + '6a' + stateHex;
  const scriptBytes = script.length / 2;
  return uint64LE(satoshis) + encodeVarint(scriptBytes) + script;
}

/**
 * Compute hashOutputs for BIP-143 from one or more serialized outputs.
 * Each output is: amount(8-byte LE) + varint(scriptLen) + script
 */
export function computeHashOutputs(outputs: string[]): string {
  if (outputs.length === 0) {
    // hash256 of empty data
    return bytesToHex(hash256(new Uint8Array(0)));
  }
  const combined = outputs.join('');
  return bytesToHex(hash256(hexToBytes(combined)));
}

/**
 * Build a complete mock BIP-143 preimage that passes all compiled contract
 * verification (checkPreimage signature check + state deserialization).
 *
 * Returns the preimage hex, the OP_PUSH_TX signature, the full locking script,
 * and the codePart (code without state).
 */
export function buildStatefulPreimage(
  params: StatefulPreimageParams,
): StatefulPreimageResult {
  const {
    artifact,
    constructorArgs,
    state,
    methodIndex = 0,
    satoshis = 10000n,
    newState,
    outputSatoshis,
    additionalOutputs = [],
    version = 1,
    locktime = 0,
    sequence = 0xffffffff,
  } = params;

  // Build code part and full locking script
  const codePart = buildCodePart(artifact, constructorArgs);
  const stateFields = artifact.stateFields ?? [];
  const lockingScript =
    stateFields.length > 0
      ? codePart + '6a' + serializeState(stateFields, state)
      : codePart;

  // Determine OP_CODESEPARATOR offset for the scriptCode
  let codeSepIndex: number | undefined;
  if (
    artifact.codeSeparatorIndices &&
    artifact.codeSeparatorIndices.length > methodIndex
  ) {
    codeSepIndex = artifact.codeSeparatorIndices[methodIndex];
  } else if (artifact.codeSeparatorIndex !== undefined) {
    codeSepIndex = artifact.codeSeparatorIndex;
  }

  // scriptCode: post-OP_CODESEPARATOR portion of the locking script.
  // The separator byte (0xab) is excluded from scriptCode.
  let scriptCode: string;
  if (codeSepIndex !== undefined) {
    scriptCode = lockingScript.slice((codeSepIndex + 1) * 2);
  } else {
    scriptCode = lockingScript;
  }

  // Build outputs
  const outputs: string[] = [];
  if (newState) {
    const outSats = outputSatoshis ?? satoshis;
    outputs.push(
      buildContinuationOutput(codePart, stateFields, newState, outSats),
    );
  }
  for (const rawOut of additionalOutputs) {
    outputs.push(rawOut);
  }

  const hashOutputsHex = computeHashOutputs(outputs);

  // Build BIP-143 preimage manually
  //
  // Format:
  //   nVersion (4 bytes LE)
  //   hashPrevouts (32 bytes)
  //   hashSequence (32 bytes)
  //   outpoint (36 bytes: txid 32 + vout 4)
  //   scriptCode (varint + script bytes)
  //   amount (8 bytes LE)
  //   nSequence (4 bytes LE)
  //   hashOutputs (32 bytes)
  //   nLocktime (4 bytes LE)
  //   sighashType (4 bytes LE)

  const nVersion = uint32LE(version);

  // Dummy outpoint: 32 zero bytes (txid) + 00000000 (vout 0)
  const dummyOutpoint = '00'.repeat(32) + '00000000';

  // hashPrevouts = hash256(outpoint)
  const hashPrevouts = bytesToHex(hash256(hexToBytes(dummyOutpoint)));

  // hashSequence = hash256(sequence as 4-byte LE)
  const hashSequence = bytesToHex(hash256(hexToBytes(uint32LE(sequence))));

  // scriptCode with varint length prefix
  const scriptCodeBytes = scriptCode.length / 2;
  const scriptCodePrefixed = encodeVarint(scriptCodeBytes) + scriptCode;

  // amount (8 bytes LE, unsigned)
  const amountHex = uint64LE(satoshis);

  // nSequence (4 bytes LE)
  const nSequence = uint32LE(sequence);

  // nLocktime (4 bytes LE)
  const nLocktime = uint32LE(locktime);

  // sighashType (4 bytes LE)
  const sighashType = uint32LE(SIGHASH_ALL_FORKID);

  const preimageHex =
    nVersion +
    hashPrevouts +
    hashSequence +
    dummyOutpoint +
    scriptCodePrefixed +
    amountHex +
    nSequence +
    hashOutputsHex +
    nLocktime +
    sighashType;

  // Sign the preimage with k=1
  // BIP-143: sighash = sha256(preimage), then PrivateKey.sign does another sha256
  // internally, so we pass sha256(preimage) to get hash256(preimage) as the
  // actual ECDSA digest.
  const preimageBytes = hexToBytes(preimageHex);
  const singleHash = sha256(preimageBytes);
  const signature = opPushTxPrivKey.sign(Array.from(singleHash));

  // Enforce low-S
  const halfN = CURVE_ORDER.div(new BigNumber(2));
  if (signature.s.gt(halfN)) {
    signature.s = CURVE_ORDER.sub(signature.s);
  }

  const derHex = signature.toDER('hex') as string;
  const signatureHex =
    derHex + SIGHASH_ALL_FORKID.toString(16).padStart(2, '0');

  return {
    preimageHex,
    signatureHex,
    lockingScript,
    codePart,
    scriptCode,
    hashOutputs: hashOutputsHex,
  };
}
