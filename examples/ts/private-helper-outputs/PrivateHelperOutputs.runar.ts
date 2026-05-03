// PrivateHelperOutputs — Audit regression: private helpers must
// propagate their side effects to the public method's continuation
// hash.
//
// # Background
//
// The 2026-04-30 TypeScript compiler audit
// (`docs/ts-compiler-audit-2026-04-30.md`) found that the compiler's
// auto-injection of stateful continuation parameters (`_changePKH`,
// `_changeAmount`, `_newAmount`, `txPreimage`) used a shallow scan of
// the public method body. A public method that delegated its side
// effect to a private helper — mutating state, emitting state outputs
// via `addOutput` / `addRawOutput`, or emitting data outputs via
// `addDataOutput` — was silently classified as terminal: the ABI
// omitted the change params, and the deployed locking script carried
// no `hashOutputs` continuation. Findings F1 (Critical) and F3
// (High) of the audit.
//
// This contract is the regression artifact: every public method
// below delegates its side effect to a private helper. A correct
// compiler must recognise the side effect and produce the same
// continuation shape as if the public method called the intrinsic
// directly.
//
// # Behavior
//
//   - `commit()` calls private `bump()` which mutates `counter`. The
//     compiler must auto-inject `_changePKH`, `_changeAmount`,
//     `_newAmount`, and `txPreimage` and emit a single-output state
//     continuation that hashes the new state script + change.
//
//   - `log(payload)` calls private `record(payload)` which emits an
//     `addDataOutput`. The compiler must inline the helper at ANF
//     time so the data output's bytes ref bubbles into the public
//     method's `addDataOutputRefs`. The continuation hash then
//     concatenates state-output || data-output || change before
//     hashing.
//
//   - `partition(amount, leftover)` calls private
//     `forkOutput(amount, leftover)` which emits `addOutput`. ANF
//     inlining lifts the helper's `add_output` ANF node into the
//     public's binding stream, registering on `addOutputRefs`. The
//     continuation hash then takes the multi-output path.
//
// # Compiler behavior
//
// ANF lowering uses a recursive side-effect summary
// (`packages/runar-compiler/src/passes/side-effect-summary.ts`,
// computed once per contract and shared with
// `artifact/assembler.ts`) that walks the private-method call
// graph. When a public stateful method calls a private helper with
// output side effects, ANF lowering inlines the helper's body
// directly into the public's binding stream so its `add_output` /
// `add_data_output` / `update_prop` ANF nodes register on the
// public's tracking lists. The continuation hash construction at
// the end of the public method's lowering then sees the correct
// output set and matches the runtime transaction's `hashOutputs`.
//
// Without inlining the refs would live in a sibling ANF method,
// stack-lowering would inline them at the byte level (so the
// outputs are pushed at runtime), but the continuation hash code
// would only reference the public's locally-tracked refs — a hash
// mismatch on chain.
//
// # Cross-compiler scope
//
// All seven Rúnar compilers (TypeScript, Go, Rust, Python, Zig,
// Ruby, Java) must produce identical Bitcoin Script for this
// contract. Cross-compiler conformance tests live in
// `conformance/tests/private-helper-outputs/` (once peer ports
// land) to lock the invariant in.
import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

export class PrivateHelperOutputs extends StatefulSmartContract {
    counter: bigint;

    constructor(counter: bigint) {
        super(counter);
        this.counter = counter;
    }

    // Pure state mutation, exposed through a private helper. The
    // public caller's continuation hash must commit to the new
    // counter value; auto-injection must therefore inject the
    // single-output continuation params (`_changePKH`,
    // `_changeAmount`, `_newAmount`, `txPreimage`).
    private bump(): void {
        this.counter = this.counter + 1n;
    }

    // `addDataOutput` called from a private helper. The public
    // caller's continuation hash must include the resulting data
    // output bytes (between the state output and the change
    // output).
    private record(payload: ByteString): void {
        this.addDataOutput(0n, payload);
    }

    // `addOutput` called from a private helper. The public caller's
    // continuation hash must commit to the explicit state output
    // via the multi-output path.
    private forkOutput(amount: bigint, leftover: bigint): void {
        this.addOutput(amount, leftover);
    }

    // Public spending entry: state mutation via private helper.
    public commit(): void {
        this.bump();
        assert(true);
    }

    // Public spending entry: data output via private helper.
    public log(payload: ByteString): void {
        this.record(payload);
        assert(true);
    }

    // Public spending entry: state output via private helper.
    public partition(amount: bigint, leftover: bigint): void {
        this.forkOutput(amount, leftover);
        assert(true);
    }
}
