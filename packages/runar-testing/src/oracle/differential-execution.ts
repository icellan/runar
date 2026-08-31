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
import { Hash, LockingScript, PrivateKey, TransactionSignature } from '@bsv/sdk';
import { SYNTHETIC_SPEND_CONTEXT } from '../vm/script-vm.js';
import { testKey } from './real-crypto-execution.js';
import { signTestMessage } from '../crypto/ecdsa.js';

export type { WitnessArg };

export interface DiffExecOptions {
  source: string;
  fileName: string; // selects the frontend parser
  method: string; // public method to spend through
  args: (WitnessArg | WitnessSignMarker)[]; // method arguments (interpreter + witness order)
  constructorArgs?: Record<string, unknown>;
  disableConstantFolding?: boolean; // default false → fold-ON deployed bytes
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

/**
 * A witness arg that must be filled with a REAL secp256k1 signature.
 *
 * The differential oracle runs the compiled script on `ScriptVM`, whose
 * OP_CHECKSIG is real secp256k1 — there is no mock. Before this, a witness
 * could only carry literal bytes, so no contract calling `checkSig` could have
 * one: any literal would fail the VM while the ANF interpreter (which mocks
 * checkSig) accepted, and the oracle would report a divergence that is an
 * artefact of the harness rather than a defect. That is why `oracle-price` —
 * the fixture pinning `verifyRabinSig` — had no witness, and why the BUG-011
 * digest-encoding defect went unexecuted all the way to RC.
 *
 * `signWith` names a key from `oracle/real-crypto-execution.ts`'s test-key
 * table, so a witness and a real-crypto witness can use the same identities.
 */
export interface WitnessSignMarker {
  signWith: string;
}

export function isWitnessSignMarker(v: unknown): v is WitnessSignMarker {
  return typeof v === 'object' && v !== null && typeof (v as WitnessSignMarker).signWith === 'string';
}

/**
 * Build the DER checksig-format signature the VM will accept for `lockingHex`.
 *
 * The preimage is derived from `SYNTHETIC_SPEND_CONTEXT` — the very object
 * `ScriptVM` constructs its `Spend` from — rather than a local copy, because
 * the two contexts differ from the real-crypto oracle's in
 * `transactionVersion`, and version is part of the BIP-143 preimage. A copied
 * constant that drifted would produce signatures that fail to verify and read
 * as a codegen defect.
 */
function signForVm(keyName: string, lockingHex: string): Uint8Array {
  const scope = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;
  const preimage = TransactionSignature.formatBytes({
    ...SYNTHETIC_SPEND_CONTEXT,
    otherInputs: [],
    outputs: [],
    subscript: LockingScript.fromHex(lockingHex),
    scope,
  });
  // OP_CHECKSIG hashes twice; `sign()` does one sha256 internally, so pre-hash once.
  const digest = Hash.sha256(Array.from(preimage));
  const key = PrivateKey.fromHex(testKey(keyName).privKey);
  const sig = key.sign(digest);
  return new Uint8Array(new TransactionSignature(sig.r, sig.s, scope).toChecksigFormat());
}

export function runDifferentialExecution(opts: DiffExecOptions): DiffExecResult {
  const ctor = normaliseCtor(opts.constructorArgs);

  // 1. Compile to deployed bytes (fold-ON by default).
  const compiled = compile(opts.source, {
    fileName: opts.fileName,
    disableConstantFolding: opts.disableConstantFolding ?? false,
    constructorArgs: ctor,
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
  // Resolve sign markers against the DEPLOYED bytes: the sighash subscript is
  // the locking script, so the signature can only be built after compiling.
  const resolvedArgs: WitnessArg[] = opts.args.map((a) =>
    isWitnessSignMarker(a) ? signForVm(a.signWith, lockingHex) : a,
  );
  const witnessArgs: WitnessArg[] =
    publicMethods.length > 1 ? [...resolvedArgs, BigInt(publicIndex)] : [...resolvedArgs];

  // 2. Source-semantics oracle: run the method through the ANF interpreter.
  //    TestContract.call reports a failed assert via `success: false` (it does
  //    NOT throw); we also catch genuine interpreter errors defensively.
  let interpreterAccepted: boolean;
  let interpreterError: string | undefined;
  try {
    const tc = TestContract.fromSource(opts.source, ctor, opts.fileName);
    const named: Record<string, unknown> = {};
    methodNode.params.forEach((p, i) => {
      const a = opts.args[i];
      // The two oracles verify a signature against DIFFERENT messages, so one
      // signature cannot satisfy both:
      //   * interpreter — real ECDSA over the fixed TEST_MESSAGE
      //     (`crypto/ecdsa.ts`, NOT a mock despite older docs saying so);
      //   * ScriptVM    — real secp256k1 over the BIP-143 sighash of the
      //     synthetic spend context.
      // A sign marker is therefore resolved per side, each valid in its own
      // domain. Handing one side the other's signature would report a signing
      // convention mismatch as a source-vs-script divergence.
      named[p.name] = isWitnessSignMarker(a)
        ? hexToBytes(signTestMessage(testKey(a.signWith).privKey))
        : a;
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
