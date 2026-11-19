/**
 * Field-usage validation for per-method `@sighash` modes (issue #123).
 *
 * SECURITY CORE. A relaxed sighash flag ZEROES specific BIP-143 preimage
 * fields; a covenant that still reads one of those fields (or binds an output
 * the flag no longer commits to) is exploitable — the attacker gets a free hand
 * over exactly the part of the transaction the covenant believed it had pinned.
 * This pass rejects, at compile time, every field read / output binding that
 * becomes unsound under the method's declared mode.
 *
 * BIP-143 field availability by sighash type (✓ = signed/committed, ✗ = ZEROED):
 *
 *   field                 ALL    NONE   SINGLE   +ANYONECANPAY
 *   ---------------------------------------------------------
 *   nVersion               ✓      ✓      ✓         (unchanged)
 *   hashPrevouts           ✓      ✓      ✓         ✗   (all-inputs digest)
 *   hashSequence           ✓      ✗      ✗         ✗   (all-inputs digest)
 *   outpoint (this input)  ✓      ✓      ✓         ✓
 *   scriptCode             ✓      ✓      ✓         ✓
 *   amount (this input)    ✓      ✓      ✓         ✓
 *   nSequence(this input)  ✓      ✓      ✓         ✓
 *   hashOutputs            ✓      ✗      same-idx   (per base)
 *   nLocktime              ✓      ✓      ✓         ✓
 *
 * The extractors that read this-input / always-present fields (extractVersion,
 * extractOutpoint, extractInputIndex, extractAmount, extractSequence,
 * extractScriptCode, extractLocktime, extractSigHashType) are sound under every
 * mode and are never rejected.
 */
import type {
  ContractNode,
  MethodNode,
  Statement,
  Expression,
  SourceLocation,
} from '../ir/index.js';
import type { CompilerDiagnostic } from '../errors.js';
import { makeDiagnostic } from '../errors.js';
import { computeSideEffectSummary, continuationShape } from './side-effect-summary.js';
import {
  BASE_TYPE_MASK,
  BASE_ALL,
  BASE_NONE,
  BASE_SINGLE,
  FLAG_ANYONECANPAY,
  describeSighash,
} from './sighash-directive.js';

/** Builtins that read the all-inputs prevouts digest (zeroed under ANYONECANPAY). */
const HASHPREVOUTS_READERS = new Set(['extractHashPrevouts']);
/** Builtins that read the all-inputs sequence digest (zeroed unless pure ALL). */
const HASHSEQUENCE_READERS = new Set(['extractHashSequence']);
/** Builtins that read the outputs digest (zeroed under NONE). */
const HASHOUTPUTS_READERS = new Set(['extractOutputHash', 'extractOutputs']);
/** Intrinsic that binds a companion input's prevout script (needs hashPrevouts). */
const PREVOUT_SCRIPT_INTRINSICS = new Set(['extractPrevOutputScript']);
/** Intrinsics that assert an output (bound via hashOutputs). */
const OUTPUT_ASSERT_INTRINSICS = new Set(['requireOutputP2PKH']);
/** Output-emitting intrinsics (state continuation outputs). */
const STATE_OUTPUT_INTRINSICS = new Set(['addOutput', 'addRawOutput']);
const DATA_OUTPUT_INTRINSICS = new Set(['addDataOutput']);

interface Usage {
  name: string;
  loc?: SourceLocation;
}

interface MethodScan {
  /** All flagged builtin/intrinsic usages by category (with source locations). */
  hashPrevoutsReads: Usage[];
  hashSequenceReads: Usage[];
  hashOutputsReads: Usage[];
  prevoutScriptReads: Usage[];
  outputAsserts: Usage[];
  /** Count of explicit output-emitting intrinsic calls. */
  stateOutputCount: number;
  dataOutputCount: number;
}

/**
 * Validate every public method's `@sighash` field usage. Returns error
 * diagnostics (empty when all modes are used soundly). Methods with no
 * directive (default ALL|FORKID) are never flagged.
 */
export function validateSighashUsage(contract: ContractNode): CompilerDiagnostic[] {
  const errors: CompilerDiagnostic[] = [];
  const isStateful = contract.parentClass === 'StatefulSmartContract';
  const sideEffects = computeSideEffectSummary(contract);

  const privateByName = new Map<string, MethodNode>();
  for (const m of contract.methods) {
    if (m.visibility === 'private') privateByName.set(m.name, m);
  }

  for (const method of contract.methods) {
    if (method.visibility !== 'public') continue;
    if (method.sighashType === undefined) continue; // default ALL|FORKID — allow all

    const mode = method.sighashType;
    const base = mode & BASE_TYPE_MASK;
    const acp = (mode & FLAG_ANYONECANPAY) !== 0;
    const label = describeSighash(mode);

    const scan = scanMethod(method, privateByName);

    // ---- state-continuation binding (stateful auto-injected hashOutputs) ----
    const effects = sideEffects.get(method.name);
    const needsContinuation =
      isStateful && !!effects && continuationShape(effects).needsChange;

    const push = (u: Usage, msg: string) =>
      errors.push(makeDiagnostic(msg, 'error', u.loc ?? method.sourceLocation));
    const pushWarn = (u: Usage, msg: string) =>
      errors.push(makeDiagnostic(msg, 'warning', u.loc ?? method.sourceLocation));

    // ---- ANYONECANPAY: only THIS input is signed --------------------------
    if (acp) {
      for (const u of scan.hashPrevoutsReads) {
        push(u, `@sighash ${label}: '${u.name}' reads hashPrevouts, which is zeroed under ANYONECANPAY (only this input is signed) — the covenant cannot constrain the input set, so any check on it is trivially bypassable. Remove ANYONECANPAY or drop the ${u.name} read.`);
      }
      for (const u of scan.prevoutScriptReads) {
        push(u, `@sighash ${label}: '${u.name}' binds a companion input's prevout script, but ANYONECANPAY zeroes hashPrevouts so the input set is unconstrained — an attacker can substitute inputs freely. Companion-input covenants require the full prevout set to be committed (drop ANYONECANPAY).`);
      }
    }

    // ---- hashSequence is committed only under pure ALL (no ACP) -----------
    const hashSequenceSound = base === BASE_ALL && !acp;
    if (!hashSequenceSound) {
      for (const u of scan.hashSequenceReads) {
        push(u, `@sighash ${label}: '${u.name}' reads hashSequence, which is zeroed under any mode other than SIGHASH_ALL (NONE / SINGLE / ANYONECANPAY all clear it) — the read yields attacker-chosen zeros. Use SIGHASH_ALL or drop the ${u.name} read.`);
      }
    }

    // ---- NONE commits to NO outputs ---------------------------------------
    if (base === BASE_NONE) {
      if (needsContinuation) {
        push({ name: 'state continuation', loc: method.sourceLocation },
          `@sighash ${label}: this stateful method binds a state-continuation output via hashOutputs, but NONE commits to NO outputs (hashOutputs is zeroed) — the continuation is unenforceable, so the next-state covenant is meaningless and the spend is unsound. A continuation covenant cannot use NONE.`);
      }
      for (const u of scan.hashOutputsReads) {
        push(u, `@sighash ${label}: '${u.name}' reads hashOutputs, which is zeroed under NONE — the read yields attacker-chosen zeros. Drop the output read or use ALL/SINGLE.`);
      }
      for (const u of scan.outputAsserts) {
        push(u, `@sighash ${label}: '${u.name}' asserts an output, but NONE commits to no outputs — the assertion cannot be enforced. Use ALL/SINGLE.`);
      }
      if (scan.stateOutputCount + scan.dataOutputCount > 0) {
        push({ name: 'addOutput', loc: method.sourceLocation },
          `@sighash ${label}: this method emits ${scan.stateOutputCount + scan.dataOutputCount} output(s) (addOutput/addRawOutput/addDataOutput), but NONE commits to no outputs — those outputs are unenforceable. Use ALL/SINGLE.`);
      }
    }

    // ---- SINGLE commits ONLY to the same-index output ---------------------
    if (base === BASE_SINGLE) {
      // A fixed-index output assertion (requireOutputP2PKH) cannot be proven to
      // land at THIS input's index, which is the only output SINGLE commits to.
      for (const u of scan.outputAsserts) {
        push(u, `@sighash ${label}: '${u.name}' asserts an output at a fixed index, but SINGLE commits ONLY to the output at THIS input's index — the asserted index cannot be statically proven equal to the input index, so the assertion may bind an uncommitted (attacker-controllable) output or silently brick the spend. Use ALL.`);
      }

      // D25: a mutate-only (auto-continuation) method under SINGLE is SOUND
      // and is the DEFAULT for a contract whose continuation methods are all
      // mutate-only (`continuation-binding.ts`). SINGLE hashes the whole
      // same-index output, value included, and the F-024 floor
      // (`_newAmount >= extractAmount`) stops a dust continuation; the change
      // is not committed (N-038). The refusal that used to stand here
      // (e88f202c8) predates both.
      const isMutateOnlyAutoContinuation =
        needsContinuation &&
        scan.stateOutputCount === 0 &&
        scan.dataOutputCount === 0;

      // Committed-output count for the multi-output rule: explicit state outputs
      // (addOutput) OR the single auto-continuation, plus any data outputs. The
      // change output is conditional (0 under an exact-cover call) and is NOT
      // counted.
      const stateOutputs =
        scan.stateOutputCount > 0
          ? scan.stateOutputCount
          : needsContinuation
            ? 1
            : 0;
      const committed = stateOutputs + scan.dataOutputCount;

      if (isMutateOnlyAutoContinuation) {
        // Sound (see above): nothing to report.
      } else if (committed > 1) {
        push({ name: 'multi-output continuation', loc: method.sourceLocation },
          `@sighash ${label}: SINGLE commits ONLY to the output at this input's index, but this method binds ${committed} outputs (${scan.stateOutputCount} addOutput + ${scan.dataOutputCount} addDataOutput${stateOutputs > scan.stateOutputCount ? ' + state continuation' : ''}). Outputs beyond the same-index one are uncommitted and attacker-controllable. A SINGLE covenant must bind exactly one same-index output.`);
      } else if (committed === 1) {
        // Legitimate pairwise input↔output covenant: exactly one explicit
        // addOutput/addRawOutput (or single data output). The same-index output
        // IS committed, but SINGLE does not let the compiler prove statically
        // that its VALUE equals the full protected amount — a runtime
        // obligation on the caller. Allow, but warn.
        pushWarn({ name: 'single-output SINGLE covenant', loc: method.sourceLocation },
          `@sighash ${label}: SINGLE commits ONLY to the output at this input's index. This method binds exactly one output there, which is sound ONLY if that output carries the FULL protected value — SINGLE does not pin the amount, so a short-changed same-index output cannot be caught at compile time. Ensure the caller places the fully-valued output at this input's index.`);
      }

      // hashSequence reads under SINGLE are already reported by the shared
      // hashSequence rule above (no double report).
    }
  }

  return errors;
}

/**
 * Walk a method body (transitively through private-method calls) collecting
 * every flagged builtin/intrinsic usage with its source location. Cycle-guarded
 * (the validator forbids recursion, but we guard defensively).
 */
function scanMethod(method: MethodNode, privateByName: Map<string, MethodNode>): MethodScan {
  const scan: MethodScan = {
    hashPrevoutsReads: [],
    hashSequenceReads: [],
    hashOutputsReads: [],
    prevoutScriptReads: [],
    outputAsserts: [],
    stateOutputCount: 0,
    dataOutputCount: 0,
  };
  const visiting = new Set<string>();

  const walkBody = (stmts: Statement[]) => {
    for (const s of stmts) walkStmt(s);
  };

  const walkStmt = (stmt: Statement) => {
    switch (stmt.kind) {
      case 'assignment':
        // Walk BOTH sides: a forbidden field read can hide in the assignment
        // target (e.g. `arr[extractOutputHash(pre)] = x`), not just the value.
        walkExpr(stmt.target);
        walkExpr(stmt.value);
        return;
      case 'expression_statement':
        walkExpr(stmt.expression);
        return;
      case 'if_statement':
        walkExpr(stmt.condition);
        walkBody(stmt.then);
        if (stmt.else) walkBody(stmt.else);
        return;
      case 'for_statement':
        // Walk the full loop header: init and condition can hide a forbidden
        // field read just as easily as the body/update do.
        walkStmt(stmt.init);
        walkExpr(stmt.condition);
        walkStmt(stmt.update);
        walkBody(stmt.body);
        return;
      case 'return_statement':
        if (stmt.value) walkExpr(stmt.value);
        return;
      case 'variable_decl':
        walkExpr(stmt.init);
        return;
      default:
        return;
    }
  };

  const calleeName = (callee: Expression): string | undefined => {
    if (callee.kind === 'identifier') return callee.name;
    if (callee.kind === 'property_access' || callee.kind === 'member_expr') return callee.property;
    return undefined;
  };

  const walkExpr = (expr: Expression) => {
    switch (expr.kind) {
      case 'call_expr': {
        const name = calleeName(expr.callee);
        const loc = expr.sourceLocation;
        if (name !== undefined) {
          if (HASHPREVOUTS_READERS.has(name)) scan.hashPrevoutsReads.push({ name, loc });
          if (HASHSEQUENCE_READERS.has(name)) scan.hashSequenceReads.push({ name, loc });
          if (HASHOUTPUTS_READERS.has(name)) scan.hashOutputsReads.push({ name, loc });
          if (PREVOUT_SCRIPT_INTRINSICS.has(name)) scan.prevoutScriptReads.push({ name, loc });
          if (OUTPUT_ASSERT_INTRINSICS.has(name)) scan.outputAsserts.push({ name, loc });
          if (STATE_OUTPUT_INTRINSICS.has(name)) scan.stateOutputCount += 1;
          if (DATA_OUTPUT_INTRINSICS.has(name)) scan.dataOutputCount += 1;
          // Recurse into a private helper so its usages surface to the caller.
          const target = privateByName.get(name);
          if (target && !visiting.has(name)) {
            visiting.add(name);
            walkBody(target.body);
            visiting.delete(name);
          }
        }
        for (const a of expr.args) walkExpr(a);
        if (expr.callee.kind !== 'identifier') walkExpr(expr.callee);
        return;
      }
      case 'binary_expr':
        walkExpr(expr.left);
        walkExpr(expr.right);
        return;
      case 'unary_expr':
        walkExpr(expr.operand);
        return;
      case 'ternary_expr':
        walkExpr(expr.condition);
        walkExpr(expr.consequent);
        walkExpr(expr.alternate);
        return;
      case 'index_access':
        walkExpr(expr.object);
        walkExpr(expr.index);
        return;
      case 'member_expr':
        walkExpr(expr.object);
        return;
      case 'property_access':
        return;
      case 'array_literal':
        for (const el of expr.elements) walkExpr(el);
        return;
      default:
        return;
    }
  };

  walkBody(method.body);
  return scan;
}
