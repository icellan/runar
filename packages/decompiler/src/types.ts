/**
 * Shared types for the decompiler pipeline.
 */

/** A single disassembled opcode with optional push data. */
export interface Op {
  /** Mnemonic name (e.g., "OP_DUP", "OP_PUSHBYTES_5"). For pushes, the raw push opcode name. */
  name: string;
  /** Raw byte value of the opcode. */
  byte: number;
  /** Push payload (only present for push opcodes). */
  data?: Uint8Array;
  /** Byte offset into the original script where this opcode starts. */
  offset: number;
  /** Total byte length of this op (opcode byte + push-length prefix + payload). */
  size: number;
}

/** A recognized builtin span replacing a sequence of opcodes after fingerprint matching. */
export interface BuiltinCall {
  kind: 'builtin_call';
  /** Builtin name as it appears in source (e.g., "ecMul"). */
  name: string;
  /** Number of stack inputs consumed. */
  arity: number;
  /** First-byte offset in the original script. */
  offset: number;
  /** Total span byte length. */
  size: number;
  /** Names of the alternative fingerprints that also matched here (for refinement). */
  alternatives?: string[];
}

/** Either a raw disassembled opcode or a recognized builtin call. */
export type AnnotatedOp =
  | (Op & { kind: 'op' })
  | BuiltinCall;

/** Per-method op stream after dispatch splitting. */
export interface MethodStream {
  /** Recovered method index (0-based) within the dispatch preamble; 0 for single-method scripts. */
  index: number;
  /** Opcode stream for this method's body, with dispatch glue removed. */
  ops: Op[];
}

/** Output of the dispatch recognizer. */
export interface DispatchResult {
  /** Number of public methods recovered (1 for single-method scripts). */
  methodCount: number;
  /** Per-method op streams. */
  methods: MethodStream[];
}

/**
 * Which recovery path produced the candidate source.
 *
 * - `template`: an exact-hex or opcode-pattern template matched. Source is
 *   the canonical one checked into `templates-data.json` / `templates.ts`.
 *   Strongest claim — the source is the real Rúnar contract.
 * - `assert-recognizer`: the lightweight symbolic recognizer matched a
 *   terminal `assert(true)` / `assert(false)` / chained-assert shape.
 *   Source uses `assert()` calls without further structural recovery.
 * - `symexec`: a symbolic-stack lifter walked a straight-line stateless body
 *   (no control flow), produced real ANF bindings (`load_param`,
 *   `load_const`, `bin_op`, `unary_op`, `call`, `assert`), inferred param
 *   types from operand provenance, and round-tripped via the source path.
 *   Stronger than `raw_script` — the recovered source carries real Rúnar
 *   expressions instead of opaque `asm({...})`.
 * - `raw_script`: fell through to the byte-canonical floor. Source wraps
 *   the entire input in a single `asm({...})` call. Honest output — no
 *   structural claim, only byte-identity.
 */
export type RecoveryPath = 'template' | 'assert-recognizer' | 'symexec' | 'raw_script';

/** Decompile result returned to callers. */
export interface DecompileResult {
  ok: boolean;
  source: string;
  attempts: number;
  diff?: VerifyDiff;
  /** Which recovery layer produced this candidate. */
  recoveryPath: RecoveryPath;
}

export type VerifyResult =
  | { ok: true }
  | { ok: false; kind: 'compile-error'; message: string }
  | VerifyDiff;

export interface VerifyDiff {
  ok: false;
  kind: 'byte-diff';
  divergenceOffset: number;
  targetSlice: Uint8Array;
  candidateSlice: Uint8Array;
}

/** Fingerprint database entry. */
export interface Fingerprint {
  /** Builtin name. */
  name: string;
  /** Number of stack inputs the call consumes (excludes constant-folded operands). */
  arity: number;
  /** Total byte length of the matched template. */
  length: number;
  /** Normalized opcode bytes (hex string) used for matching. */
  normalizedHex: string;
  /** Stable hash of normalizedHex for quick lookup. */
  hash: string;
}

export interface FingerprintDB {
  /** Compiler version under which the DB was generated. */
  compilerVersion: string;
  /** Generation timestamp (ISO 8601). */
  generatedAt: string;
  /** Entries indexed by builtin name. Multiple entries per name are allowed (variants). */
  entries: Fingerprint[];
}
