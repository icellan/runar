/**
 * Source-vs-script differential-execution oracle (TS-GAP-001).
 *
 * Runs the same spend attempt through two independent engines:
 *   1. source semantics — the AST-walking `RunarInterpreter` (via `TestContract`)
 *   2. script semantics — the compiled Bitcoin Script on the `@bsv/sdk`-backed
 *      `ScriptVM`
 * on the compiler's **fold-ON deployed bytes** (the shipped default), and
 * asserts they agree on accept/reject.
 *
 * What this DOES catch: a codegen bug downstream of ANF lowering
 * (stack-lower / emit) that makes the compiled script diverge from the
 * interpreter's independent read of the same source semantics — the two
 * engines consume the IR at different pipeline stages, so they can disagree
 * when only one side is wrong.
 *
 * What this does NOT prove (testing-gap remediation Phase B / TG-008):
 * accept/reject AGREEMENT is not evidence of a correct post-spend STATE, and
 * it does not mean "a bug shared by all seven compilers is always caught".
 * This oracle compares VERDICTS ONLY. The two engines share just
 * parse/validate/typecheck: the interpreter (`TestContract` →
 * `RunarInterpreter.executeMethod`, see `test-contract.ts` /
 * `interpreter/interpreter.ts`) reads the parsed AST (`ContractNode`)
 * directly, and `04-anf-lower.ts` sits downstream of that input — it is NOT
 * shared with the interpreter. So this oracle CAN disagree with, and catch,
 * a miscompile in ANF lowering / stack-lower / emit — but ONLY when the bug
 * flips accept/reject. A miscompile that leaves the script acceptable while
 * committing the WRONG continuation state (the PALMER-1 class' Face B:
 * branch-merged locals producing a wrong-but-self-consistent continuation
 * that both engines happily "accept") is invisible to a verdict-only
 * comparison — this oracle reports `agrees: true` while the state is wrong.
 * Catching that needs an INDEPENDENT, hand-authored pin that is not derived
 * from this pipeline — `expectedState` in
 * `conformance/witnesses/real-crypto/*.json` (machine-checked by
 * `coverage-claims.test.ts`, enforced at run time by
 * `real-crypto-execution.test.ts`) or an external KAT vector — not this
 * oracle's own accept/reject agreement.
 */
import { compile } from 'runar-compiler';
import { ScriptVM, hexToBytes, bytesToHex } from '../vm/index.js';
import { TestContract } from '../test-contract.js';
import { buildWitness, type WitnessArg } from './witness.js';

export type { WitnessArg };

export interface DiffExecOptions {
  source: string;
  fileName: string; // selects the frontend parser
  method: string; // public method to spend through
  args: WitnessArg[]; // method arguments (interpreter + witness order)
  constructorArgs?: Record<string, unknown>;
  disableConstantFolding?: boolean; // default false → fold-ON deployed bytes
  /**
   * EXPERIMENTAL backend toggles. Present so a size experiment can be run
   * through this same source-vs-script oracle: compile the SAME contract with
   * a flag off and on, execute both on the SAME witness, and require identical
   * acceptance. Both default to the shipping path.
   */
  schedulerMode?: 'current' | 'liveness';
  ecConstantPool?: boolean;
  ecReductionSinking?: boolean;
  ecFixedBaseComb?: boolean;
}

export interface DiffExecResult {
  interpreterAccepted: boolean; // did the ANF interpreter accept (no failed assert)?
  vmAccepted: boolean; // did the compiled script verify on the BSV engine?
  agrees: boolean; // interpreterAccepted === vmAccepted
  lockingHex: string;
  witnessHex: string;
  interpreterError?: string;
  vmError?: string;
}

/**
 * Normalise constructor args to the primitive union the compiler and the
 * interpreter both accept: bigint | boolean | string (hex, no 0x prefix).
 * `TestContract`'s toRunarValue and `compile`'s constructorArgs both read a
 * bare string as hex bytes, so a single normalised record feeds both.
 */
function normaliseCtor(
  ctor: Record<string, unknown> | undefined,
): Record<string, bigint | boolean | string> {
  const out: Record<string, bigint | boolean | string> = {};
  for (const [k, v] of Object.entries(ctor ?? {})) {
    if (v instanceof Uint8Array) out[k] = bytesToHex(v);
    else if (typeof v === 'bigint' || typeof v === 'boolean' || typeof v === 'string') out[k] = v;
    else throw new Error(`unconvertible constructor arg ${k}: ${typeof v}`);
  }
  return out;
}

export function runDifferentialExecution(opts: DiffExecOptions): DiffExecResult {
  const ctor = normaliseCtor(opts.constructorArgs);

  // 1. Compile to deployed bytes (fold-ON by default).
  const compiled = compile(opts.source, {
    fileName: opts.fileName,
    disableConstantFolding: opts.disableConstantFolding ?? false,
    constructorArgs: ctor,
    schedulerMode: opts.schedulerMode,
    ecConstantPool: opts.ecConstantPool,
    ecReductionSinking: opts.ecReductionSinking,
    ecFixedBaseComb: opts.ecFixedBaseComb,
  });
  if (!compiled.success || !compiled.artifact) {
    const errs = compiled.diagnostics
      .filter((d) => d.severity === 'error')
      .map((d) => d.message)
      .join('; ');
    throw new Error(`compile failed for ${opts.fileName}: ${errs}`);
  }
  const lockingHex = compiled.artifact.script;

  // Resolve the method's parameter names so positional witness args map to the
  // interpreter's named-argument calling convention.
  const methodNode = compiled.contract?.methods.find((m) => m.name === opts.method);
  if (!methodNode) {
    throw new Error(`method ${opts.method} not found in ${opts.fileName}`);
  }
  if (methodNode.params.length !== opts.args.length) {
    throw new Error(
      `arg count mismatch for ${opts.method}: source declares ${methodNode.params.length}, got ${opts.args.length}`,
    );
  }

  // Multi-method dispatch: when a contract has more than one public spending
  // entry point, the compiled locking script selects the branch by a method
  // index pushed on TOP of the unlocking stack (public methods numbered from 0
  // in declaration order). Single-method contracts have no selector. The
  // interpreter selects by name, so the selector is a VM-witness-only concern.
  const publicMethods = (compiled.contract?.methods ?? []).filter(
    (m) => m.visibility === 'public' && m.name !== 'constructor',
  );
  const publicIndex = publicMethods.findIndex((m) => m.name === opts.method);
  const witnessArgs: WitnessArg[] =
    publicMethods.length > 1 ? [...opts.args, BigInt(publicIndex)] : [...opts.args];

  // 2. Source-semantics oracle: run the method through the ANF interpreter.
  //    TestContract.call reports a failed assert via `success: false` (it does
  //    NOT throw); we also catch genuine interpreter errors defensively.
  let interpreterAccepted: boolean;
  let interpreterError: string | undefined;
  try {
    const tc = TestContract.fromSource(opts.source, ctor, opts.fileName);
    const named: Record<string, unknown> = {};
    methodNode.params.forEach((p, i) => {
      named[p.name] = opts.args[i];
    });
    const res = tc.call(opts.method, named);
    interpreterAccepted = res.success;
    if (!res.success) interpreterError = res.error;
  } catch (e) {
    interpreterAccepted = false;
    interpreterError = e instanceof Error ? e.message : String(e);
  }

  // 3. Script-semantics oracle: run the compiled script on the BSV engine.
  const witness = buildWitness(witnessArgs);
  const witnessHex = bytesToHex(witness);
  let vmAccepted: boolean;
  let vmError: string | undefined;
  try {
    // `strictEncoding` is REQUIRED, not optional polish. `ScriptVM` passes
    // `isRelaxed: this.flags.strictEncoding !== true` to `@bsv/sdk`, so a bare
    // `new ScriptVM()` runs the script with `fromScriptNum`'s minimal-encoding
    // check DISABLED. This oracle's whole job is to compare source semantics
    // against what a node does — and a node enforces minimal encoding.
    //
    // Left relaxed, the VM side silently accepts a non-minimal operand (e.g.
    // `1 >> 1` = [0x00] feeding a numeric op) that a real node ABORTS on, so
    // the oracle reported "agreement" precisely where the funds-locking
    // divergence lives, and would have reported a FALSE divergence once the
    // interpreter was corrected to match consensus.
    const vm = new ScriptVM({ flags: { strictEncoding: true } });
    const res = vm.execute(witness, hexToBytes(lockingHex));
    vmAccepted = res.success;
    if (!res.success) vmError = res.error;
  } catch (e) {
    vmAccepted = false;
    vmError = e instanceof Error ? e.message : String(e);
  }

  return {
    interpreterAccepted,
    vmAccepted,
    agrees: interpreterAccepted === vmAccepted,
    lockingHex,
    witnessHex,
    interpreterError,
    vmError,
  };
}
