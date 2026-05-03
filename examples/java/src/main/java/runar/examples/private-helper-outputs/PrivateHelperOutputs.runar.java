package runar.examples.privatehelperoutputs;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;

/**
 * PrivateHelperOutputs -- audit regression: private helpers must
 * propagate their side effects to the public method's continuation
 * hash.
 *
 * <h2>Background</h2>
 *
 * <p>The 2026-04-30 TypeScript compiler audit
 * (<code>docs/ts-compiler-audit-2026-04-30.md</code>) found that the
 * compiler's auto-injection of stateful continuation parameters
 * (<code>_changePKH</code>, <code>_changeAmount</code>,
 * <code>_newAmount</code>, <code>txPreimage</code>) used a shallow scan
 * of the public method body. A public method that delegated its side
 * effect to a private helper -- mutating state, emitting state outputs
 * via {@code addOutput} / {@code addRawOutput}, or emitting data
 * outputs via {@code addDataOutput} -- would silently be classified as
 * terminal, the ABI would omit the change params, and the deployed
 * locking script would carry no <code>hashOutputs</code> continuation.
 * Findings F1 (Critical) and F3 (High) of the audit.
 *
 * <p>This contract is the regression artifact: every public method
 * below delegates its side effect to a private helper. A correct
 * compiler must recognise the side effect and produce the same
 * continuation shape as if the public method called the intrinsic
 * directly.
 *
 * <h2>Behavior</h2>
 *
 * <ul>
 *   <li>{@link #commit()} calls private {@link #bump()} which mutates
 *     {@code counter}. The continuation must carry the new counter
 *     value forward via the single-output state-continuation path.</li>
 *   <li>{@link #log(ByteString)} calls private
 *     {@link #record(ByteString)} which emits {@code addDataOutput}.
 *     The continuation must hash the data output bytes between the
 *     state output and the change output.</li>
 *   <li>{@link #partition(Bigint, Bigint)} calls private
 *     {@link #forkOutput(Bigint, Bigint)} which emits
 *     {@code addOutput}. The continuation must hash the explicit
 *     state output via the multi-output path.</li>
 * </ul>
 *
 * <h2>Compiler behavior</h2>
 *
 * <p>ANF lowering uses a recursive side-effect summary (computed once
 * per contract, shared with the ABI assembler) that walks the
 * private-method call graph. When a public stateful method calls a
 * private helper with output side effects, ANF lowering inlines the
 * helper's body into the public's binding stream so its
 * {@code add_output} / {@code add_data_output} ANF nodes register on
 * the public's {@code addOutputRefs} / {@code addDataOutputRefs}. The
 * continuation hash construction then sees the correct output set and
 * matches the runtime transaction's {@code hashOutputs}.
 *
 * <h2>Cross-compiler scope</h2>
 *
 * <p>All seven Rúnar compilers (TypeScript, Go, Rust, Python, Zig,
 * Ruby, Java) must produce identical Bitcoin Script for this contract;
 * the fix and its tests live in the conformance suite to lock that
 * invariant in.
 */
class PrivateHelperOutputs extends StatefulSmartContract {

    Bigint counter;

    PrivateHelperOutputs(Bigint counter) {
        super(counter);
        this.counter = counter;
    }

    // Method declaration order matches the TypeScript canonical fixture
    // (privates before publics) so the seven-compiler ANF IR stays
    // byte-identical against
    // {@code conformance/tests/private-helper-outputs/expected-ir.json}.

    /** Pure state mutation, exposed through a private helper. */
    void bump() {
        this.counter = this.counter.plus(Bigint.ONE);
    }

    /** {@code addDataOutput} called from a private helper. */
    void record(ByteString payload) {
        this.addDataOutput(0L, payload);
    }

    /** {@code addOutput} called from a private helper. */
    void forkOutput(Bigint amount, Bigint leftover) {
        this.addOutput(amount, leftover);
    }

    /** Calls a private state-mutating helper. */
    @Public
    void commit() {
        bump();
        assertThat(true);
    }

    /** Routes a data output through a private helper. */
    @Public
    void log(ByteString payload) {
        record(payload);
        assertThat(true);
    }

    /** Routes a state output through a private helper. */
    @Public
    void partition(Bigint amount, Bigint leftover) {
        forkOutput(amount, leftover);
        assertThat(true);
    }
}
