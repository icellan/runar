package runar.integration.helpers;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.function.Executable;

import runar.integration.helpers.RpcProvider.BroadcastKind;
import runar.integration.helpers.RpcProvider.BroadcastOutcome;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Negative tests must prove the NODE rejected the spend.
 *
 * <p>{@code assertThrows(RuntimeException.class, ...)} plus a moved
 * {@link RpcProvider#broadcastAttempts()} counter used to be the pattern, and
 * since GK-BUG-004 it is vacuous: an ACCEPTED transaction whose confirming mine
 * fails also throws after an attempt. {@link #assertNodeRejected} instead reads
 * what each broadcast of the call came to ({@link RpcProvider#broadcastLog()}).
 */
public final class NodeRejection {

    /**
     * The reason SV Node gives for a spend whose unlocking script fails (a false
     * assert, a failed checkSig, a script error such as OP_SPLIT out of range).
     */
    public static final String SCRIPT_VERIFY_FAILED = "mandatory-script-verify-flag-failed";

    private NodeRejection() {}

    /**
     * Runs {@code call} and asserts the node refused it with {@code reason}.
     * Returns the call's exception.
     */
    public static RuntimeException assertNodeRejected(RpcProvider provider, Executable call, String reason) {
        int before = provider.broadcastLog().size();
        RuntimeException e = assertThrows(RuntimeException.class, call,
            "the spend was ACCEPTED, so nothing was rejected");
        List<BroadcastOutcome> log = provider.broadcastLog();
        check(log.subList(before, log.size()), reason).ifPresent(why ->
            fail("not a node rejection: " + why + "; call error: " + e));
        return e;
    }

    /**
     * The pure check behind {@link #assertNodeRejected}. {@code added} is what
     * the call under test broadcast. Empty when, and only when:
     * <ol>
     *   <li>the call broadcast at least once (an exception with no broadcast is
     *       an SDK-side refusal, not consensus),</li>
     *   <li>the node accepted none of those broadcasts — including an accepted
     *       tx whose confirming mine then failed,</li>
     *   <li>the last one was refused by the node at sendrawtransaction with a
     *       message containing {@code reason}.</li>
     * </ol>
     */
    public static Optional<String> check(List<BroadcastOutcome> added, String reason) {
        if (added.isEmpty()) {
            return Optional.of("the call never handed a transaction to the node (SDK-side failure)");
        }
        for (BroadcastOutcome o : added) {
            if (o.kind() == BroadcastKind.ACCEPTED || o.kind() == BroadcastKind.ACCEPTED_MINE_FAILED) {
                return Optional.of("the node ACCEPTED a transaction from this call: " + o);
            }
        }
        BroadcastOutcome last = added.get(added.size() - 1);
        if (last.kind() != BroadcastKind.NODE_REJECTED) {
            return Optional.of("the node never ruled on the spend: " + last);
        }
        if (!last.detail().contains(reason)) {
            return Optional.of("the node rejected the spend for the wrong reason: expected '" + reason
                + "', got '" + last.detail() + "'");
        }
        return Optional.empty();
    }
}
