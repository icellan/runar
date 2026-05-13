/**
 * runar-decompiler — public entry.
 *
 * Two recovery paths:
 *
 *   1. **Template path** — exact-hex or opcode-pattern match against a
 *      checked-in canonical source. Source compiles back to byte-identical
 *      hex. Verification runs against the source via `compile()`.
 *
 *   2. **Raw-script path** — wrap the disassembled bytes (or a non-matching
 *      span) in a single `raw_script` ANF node. The result is an
 *      `ANFProgram` whose verification runs through `compileFromANF()` —
 *      no TS surface syntax required, which keeps this path independent of
 *      Phase 3 (`asm({...})` parsing). The wrapped bytes emit verbatim
 *      because the peephole optimizer treats `raw_bytes` as a hard barrier.
 *
 * `decompile(...)` chooses the path: template first, raw_script fallback.
 * The `raw: true` option short-circuits templates and forces the raw_script
 * floor, which is what `runar decompile --raw` invokes.
 */

import { hexToBytes } from 'runar-testing';
import type { ANFProgram, StateField } from 'runar-compiler';
import { disassemble } from './disasm.js';
import { splitMethods } from './dispatch.js';
import { matchFingerprints } from './match.js';
import { runSymbolic } from './symexec.js';
import { lift, buildRawScriptProgram } from './lift.js';
import { emitTs, emitRawScriptSource } from './emit-ts.js';
import { verifyDecompilation, verifyDecompilationAnf } from './verify.js';
import { loadFingerprints } from './fingerprints.js';
import { tryTemplates } from './templates.js';
import { liftStraightLine, liftMultiMethod, renderTsSource } from './symexec-lift.js';
import { liftStatefulFromArtifact, renderStatefulSource } from './stateful-lift.js';
import { runRefinement } from './refine.js';
import type { DecompileResult, FingerprintDB, VerifyDiff } from './types.js';

export interface DecompileOptions {
  /** Optional pre-loaded fingerprint DB. Otherwise loaded from the package default. */
  db?: FingerprintDB;
  /** Class name for the emitted recovered source. Defaults to `_Recovered`. */
  className?: string;
  /**
   * Maximum refinement attempts per recovery layer. The first attempt is
   * the layer's initial candidate; subsequent attempts cycle through the
   * refinement strategies (`alt-fingerprint` → `type-swap` → `branch-swap`).
   * Defaults to 5 (matches the original v0 plan).
   */
  maxAttempts?: number;
  /**
   * Force the raw_script path: skip templates and the symbolic recognizer,
   * wrap the entire input in a single `raw_script` ANF node, verify via
   * `compileFromANF`. Honest output — round-trips byte-identically for any
   * Bitcoin Script byte stream (Rúnar-produced or not).
   */
  raw?: boolean;
  /**
   * Constructor parameter placeholder byte offsets, copied verbatim from the
   * artifact's `constructorSlots`. When supplied, the symexec layer recovers
   * `OP_0` at those offsets as `load_prop` references (synthesized as
   * `this.prop<paramIndex>`) instead of literal `0n` pushes — the recovered
   * source then declares the matching `public readonly` properties and the
   * re-compiled bytes line up at the same offsets. Without this, scripts
   * that use constructor placeholders silently fall through to raw_script.
   */
  constructorSlots?: Array<{ paramIndex: number; byteOffset: number }>;
  /**
   * State-field descriptors from the artifact (`stateFields`). When this is
   * non-empty OR `codeSeparatorIndex` / `codeSeparatorIndices` is defined,
   * the decompiler routes through the stateful path (auto-injected prelude
   * and continuation are stripped from the ANF before rendering).
   */
  stateFields?: readonly StateField[];
  /**
   * OP_CODESEPARATOR byte offset from the artifact (single-method shape).
   * Presence routes through the stateful path; the value itself is
   * informational (used to bound the user-code span when the lifter ever
   * needs to operate on bytes instead of the ANF).
   */
  codeSeparatorIndex?: number;
  /** Per-method OP_CODESEPARATOR byte offsets (multi-method shape). */
  codeSeparatorIndices?: readonly number[];
  /**
   * Explicit parent-class hint. Inferred from `stateFields` /
   * `codeSeparatorIndex` when omitted: presence of either implies
   * `StatefulSmartContract`, otherwise `SmartContract`.
   */
  parentClass?: 'SmartContract' | 'StatefulSmartContract';
  /**
   * Optional ANF program copied verbatim from the artifact. The stateful
   * recovery path operates on this directly — it strips auto-injected
   * prelude/continuation bindings from each public method, then renders
   * the user-visible remainder as a TS Rúnar source string. Round-trips
   * byte-identically when the artifact's ANF is the source-compile
   * canonical form (which is what the assembler emits).
   */
  anf?: ANFProgram;
}

export function decompile(target: Uint8Array | string, opts: DecompileOptions = {}): DecompileResult {
  const bytes = typeof target === 'string' ? hexToBytes(target) : target;

  // --raw / opts.raw — skip templates, wrap bytes in raw_script, verify via ANF.
  if (opts.raw) {
    return decompileViaRawScript(bytes, opts);
  }

  const db = opts.db ?? loadFingerprints();
  const ops = disassemble(bytes);
  const maxAttempts = opts.maxAttempts ?? 5;

  // Detect stateful artifact info — inferred from `stateFields`,
  // `codeSeparatorIndex(es)`, `parentClass`, or an explicit ANF. Routing
  // through the stateful path is opt-IN via these fields; when the caller
  // doesn't have access to the artifact, behavior matches the previous
  // (stateless-only) pipeline exactly.
  const isStatefulArtifact =
    (opts.stateFields !== undefined && opts.stateFields.length > 0) ||
    opts.codeSeparatorIndex !== undefined ||
    (opts.codeSeparatorIndices !== undefined && opts.codeSeparatorIndices.length > 0) ||
    opts.parentClass === 'StatefulSmartContract';

  // Layer 1 — exact-hex / opcode-pattern template match.
  const tpl = tryTemplates(ops);
  if (tpl !== null) {
    const result = verifyDecompilation(bytes, tpl);
    if (result.ok) return { ok: true, source: tpl, attempts: 1, recoveryPath: 'template' };
    if (result.kind === 'byte-diff') {
      // Refinement loop. Templates don't carry a LiftResult, so only
      // strategy 1 (alt-fingerprint) could fire — and that's a documented
      // no-op today. The loop terminates cleanly and we fall through.
      const refined = runRefinement({
        maxAttempts,
        initialDiff: result,
        initialCandidate: tpl,
        className: opts.className,
        verify: src => verifyDecompilation(bytes, src),
      });
      if (refined.source !== null) {
        return { ok: true, source: refined.source, attempts: refined.attempts, recoveryPath: 'template' };
      }
      // Fall through to next layer on exhaustion (raw_script floor still
      // gives byte-identity).
    }
    // For compile-error or refinement exhaustion, fall through.
  }

  // Layer 2 — symbolic recognizer for simple assert-only bodies. Falls back
  // to the raw_script path when the recognizer can't model the span.
  const split = splitMethods(ops);
  const liftedMethods = split.methods.map(m => {
    const annotated = matchFingerprints(m.ops, { db });
    const ssa = runSymbolic(annotated, m.index);
    return lift(ssa);
  });

  // If every method's body is a recognized terminal-assert shape, emit
  // the assert-based source. Otherwise fall through to raw_script — the
  // only path that gives an honest byte-identity guarantee.
  const allRecognized = liftedMethods.every(m =>
    m.bindings.every(b => b.kind === 'assert_const' || b.kind === 'assert_chain'),
  );
  if (allRecognized) {
    const source = emitTs(liftedMethods, { className: opts.className });
    const result = verifyDecompilation(bytes, source);
    if (result.ok) return { ok: true, source, attempts: 1, recoveryPath: 'assert-recognizer' };
    if (result.kind === 'byte-diff') {
      // Recognizer was wrong about the shape; refinement strategies don't
      // structurally apply here (no LiftResult), so the loop terminates
      // immediately and we fall through to raw_script.
      const refined = runRefinement({
        maxAttempts,
        initialDiff: result,
        initialCandidate: source,
        className: opts.className,
        verify: src => verifyDecompilation(bytes, src),
      });
      if (refined.source !== null) {
        return { ok: true, source: refined.source, attempts: refined.attempts, recoveryPath: 'assert-recognizer' };
      }
    }
  }

  // Layer 2.5 — stateful artifact-driven recovery. Triggered when the
  // caller passes `stateFields`, `codeSeparatorIndex(es)`, `parentClass:
  // 'StatefulSmartContract'`, or `anf` directly. We strip the auto-injected
  // prelude (`check_preimage` + `deserialize_state`) and continuation
  // (`buildChangeOutput` / `computeStateOutput` / `hash256` /
  // `extractOutputHash` / `===` / `assert`) from every public method of
  // the supplied ANF, then render the user-visible remainder as TS source
  // and re-compile to verify byte-identity. Aborts cleanly to the symexec
  // / raw_script floor when the ANF carries shapes we don't strip (e.g.
  // private-helper outputs whose continuation hash doesn't see the
  // helper's `add_output` refs).
  if (isStatefulArtifact && opts.anf) {
    const lifted = liftStatefulFromArtifact(opts.anf, {
      stateFields: opts.stateFields,
      className: opts.className,
    });
    if (lifted.ok) {
      const source = renderStatefulSource(lifted, { className: opts.className });
      const verify = verifyDecompilation(bytes, source);
      if (verify.ok) {
        return { ok: true, source, attempts: 1, recoveryPath: 'symexec' };
      }
      // Surface round-trip diverged. Fall through to the existing symexec
      // / raw_script floor — those paths will likely also fail for true
      // stateful shapes, but we don't synthesize a false-positive.
    }
    // Lift failure: fall through.
  }

  // Layer 3 — symbolic-stack lifter. For single-method scripts, runs the
  // straight-line lifter directly on the body. For multi-method scripts
  // (dispatch preamble detected by `splitMethods`), runs the lifter on
  // each per-method op stream and merges into a single ANFProgram whose
  // `methods[]` array carries one entry per recovered method. Either
  // shape aborts cleanly to raw_script on any unsupported opcode or
  // verification divergence — and for the multi-method case, ANY method
  // failing aborts the whole script (no partial recovery across the
  // dispatch boundary, which would break the method-index ABI).
  const liftRes = split.methodCount === 1
    ? liftStraightLine(split.methods[0]!.ops, {
        className: opts.className,
        methodName: '_method0',
        constructorSlots: opts.constructorSlots,
      })
    : liftMultiMethod(split.methods, {
        className: opts.className,
        constructorSlots: opts.constructorSlots,
      });
  if (liftRes.ok) {
    const source = renderTsSource(liftRes, { className: opts.className });
    const verifyAnf = verifyDecompilationAnf(bytes, liftRes.program);
    // We require BOTH (a) the rendered source re-compiles to the same
    // bytes (TS surface round-trip), and (b) the underlying ANF
    // re-compiles to the same bytes (compileFromANF round-trip).
    if (verifyAnf.ok) {
      const verifySrc = verifyDecompilation(bytes, source);
      if (verifySrc.ok) {
        return { ok: true, source, attempts: 1, recoveryPath: 'symexec' };
      }
      if (verifySrc.kind === 'byte-diff') {
        // Surface round-trip diverged but ANF round-trip already matches —
        // run the refinement loop with the LiftResult available so
        // strategies 2 (type-swap) and 3 (branch-swap) can fire.
        const refined = runRefinement({
          maxAttempts,
          initialDiff: verifySrc,
          initialCandidate: source,
          liftResult: liftRes,
          className: opts.className,
          verify: src => verifyDecompilation(bytes, src),
        });
        if (refined.source !== null) {
          return {
            ok: true,
            source: refined.source,
            attempts: refined.attempts,
            recoveryPath: 'symexec',
          };
        }
      }
    }
    // Fall through to raw_script — the lifter produced ANF but verification
    // diverged and refinement couldn't rescue it. raw_script remains
    // byte-canonical.
  }

  return decompileViaRawScript(bytes, opts);
}

/**
 * Build a single-`raw_script` ANFProgram, verify via `compileFromANF`,
 * and return a human-readable `asm({...})` source. The verification path
 * is independent of TS surface syntax; the source is for presentation.
 */
function decompileViaRawScript(bytes: Uint8Array, opts: DecompileOptions): DecompileResult {
  const program: ANFProgram = buildRawScriptProgram(bytes);
  const result = verifyDecompilationAnf(bytes, program);
  const source = emitRawScriptSource(bytes, { className: opts.className });
  if (result.ok) return { ok: true, source, attempts: 1, recoveryPath: 'raw_script' };
  const diff: VerifyDiff | undefined = result.kind === 'byte-diff' ? result : undefined;
  return { ok: false, source, attempts: 1, diff, recoveryPath: 'raw_script' };
}

// Re-exports for tests / consumers.
export { disassemble } from './disasm.js';
export { splitMethods } from './dispatch.js';
export { matchFingerprints } from './match.js';
export { runSymbolic } from './symexec.js';
export { lift, buildRawScriptProgram } from './lift.js';
export { emitTs, emitRawScriptSource } from './emit-ts.js';
export { verifyDecompilation, verifyDecompilationAnf, bytesEqual, firstDiff } from './verify.js';
export { loadFingerprints, emptyDB, entriesByLengthDesc } from './fingerprints.js';
export { tryTemplates } from './templates.js';
export {
  liftStraightLine,
  liftMultiMethod,
  renderTsSource,
  getUnhandledOpcodeCounts,
  resetUnhandledOpcodeCounts,
} from './symexec-lift.js';
export {
  liftStatefulFromArtifact,
  renderStatefulSource,
} from './stateful-lift.js';
export type {
  StatefulLiftResult,
  StatefulLiftFailure,
  StatefulLiftOutcome,
  StatefulLiftOptions,
} from './stateful-lift.js';
export {
  applyRefinement,
  runRefinement,
  REFINEMENT_STRATEGY_ORDER,
} from './refine.js';
export type {
  RefineContext,
  RefinementStrategy,
  RunRefinementOptions,
  RunRefinementResult,
  Verifier,
} from './refine.js';
export { bytesToHex, hexToBytes } from 'runar-testing';
export type {
  Op,
  AnnotatedOp,
  BuiltinCall,
  MethodStream,
  DispatchResult,
  DecompileResult,
  RecoveryPath,
  VerifyResult,
  VerifyDiff,
  Fingerprint,
  FingerprintDB,
} from './types.js';
