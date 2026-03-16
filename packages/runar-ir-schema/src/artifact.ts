/**
 * Rúnar Artifact — the final compiled output of a Rúnar compiler (Pass 6).
 *
 * This is what gets consumed by wallets, SDKs, and deployment tooling.
 * It bundles the locking script, ABI metadata, optional debug info,
 * and (for stateful contracts) state field descriptors.
 */

import type { ANFProgram } from './anf-ir.js';
import type { StackProgram } from './stack-ir.js';

// ---------------------------------------------------------------------------
// ABI
// ---------------------------------------------------------------------------

export interface ABIParam {
  name: string;
  type: string;
}

export interface ABIConstructor {
  params: ABIParam[];
}

export interface ABIMethod {
  name: string;
  params: ABIParam[];
  isPublic: boolean;
  /** True for stateful contract methods that don't mutate state (no continuation output). */
  isTerminal?: boolean;
}

export interface ABI {
  constructor: ABIConstructor;
  methods: ABIMethod[];
}

// ---------------------------------------------------------------------------
// Source map
// ---------------------------------------------------------------------------

export interface SourceMapping {
  opcodeIndex: number;
  sourceFile: string;
  line: number;
  column: number;
}

export interface SourceMap {
  mappings: SourceMapping[];
}

// ---------------------------------------------------------------------------
// Stateful contracts
// ---------------------------------------------------------------------------

export interface StateField {
  name: string;
  type: string;
  index: number;
  initialValue?: string | bigint | boolean;
}

// ---------------------------------------------------------------------------
// Constructor slots
// ---------------------------------------------------------------------------

export interface ConstructorSlot {
  paramIndex: number;
  byteOffset: number;
}

// ---------------------------------------------------------------------------
// Top-level artifact
// ---------------------------------------------------------------------------

export interface RunarArtifact {
  /** Schema version, e.g. "runar-v0.1.0" */
  version: string;

  /** Semver of the compiler that produced this artifact */
  compilerVersion: string;

  /** Name of the compiled contract */
  contractName: string;

  /** Public ABI (constructor + methods) */
  abi: ABI;

  /** Hex-encoded locking script */
  script: string;

  /** Human-readable assembly (space-separated opcodes) */
  asm: string;

  /** Optional source-level debug mappings */
  sourceMap?: SourceMap;

  /** Optional IR snapshots for debugging / conformance checking */
  ir?: {
    anf?: ANFProgram;
    stack?: StackProgram;
  };

  /** ANF IR for SDK state computation (always included for stateful contracts) */
  anf?: ANFProgram;

  /** State field descriptors (present only for stateful contracts) */
  stateFields?: StateField[];

  /** Byte offsets of constructor parameter placeholders in the script */
  constructorSlots?: ConstructorSlot[];

  /** Byte offset of OP_CODESEPARATOR in the locking script (for BIP-143 sighash) */
  codeSeparatorIndex?: number;

  /** Per-method OP_CODESEPARATOR byte offsets (index 0 = first public method, etc.). */
  codeSeparatorIndices?: number[];

  /** ISO-8601 build timestamp */
  buildTimestamp: string;
}
