package runar.lang.sdk;

import java.util.ArrayList;
import java.util.List;

/**
 * R-062 / CL-BUG-105 — deploy-time gate on builtins the project does not claim
 * are sound.
 *
 * <p>The compiler refuses to emit a script reaching {@code verifySP1FRI} unless
 * the author wrote {@code @acknowledgeUnsoundSP1FriVerifier} or the invoker
 * passed {@code --acknowledge-unsound-sp1-fri} (R-012). That acknowledgement
 * stopped at whoever ran the compiler: the artifact handed on afterwards looked
 * like any other, carried no marker of the gap, and every SDK funded it in
 * silence — which is how an acknowledged proof-of-concept verifier reaches a
 * value-bearing deployment with no friction.
 *
 * <p>The compiler now stamps {@code unsoundPrimitives} into the artifact. This
 * guard is the SDK half: the deploy path calls it BEFORE any signing or
 * broadcast, and the caller must name each listed primitive to proceed.
 *
 * <p>Deploy only, deliberately. Spending an already-deployed contract is how
 * funds are RECOVERED from one, and refusing that would strand coins whose risk
 * was taken at deploy time. The friction belongs where the value first enters.
 */
public final class UnsoundPrimitives {

    private UnsoundPrimitives() {}

    /** Thrown when an unsound primitive reaches deploy unacknowledged. */
    public static final class UnsoundPrimitiveError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public final List<String> missing;
        public final String context;

        UnsoundPrimitiveError(List<String> missing, String context, String message) {
            super(message);
            this.missing = List.copyOf(missing);
            this.context = context;
        }
    }

    /**
     * Throws unless every unsound primitive the artifact declares appears in
     * {@code acknowledged}.
     *
     * @param artifact     the artifact about to be funded
     * @param acknowledged primitives the caller explicitly accepts
     * @param context      call site for the message, e.g. {@code "Counter.deploy"}
     */
    public static void assertAcknowledged(
        RunarArtifact artifact,
        List<String> acknowledged,
        String context
    ) {
        if (artifact == null || artifact.unsoundPrimitives().isEmpty()) {
            return;
        }
        List<String> ok = acknowledged == null ? List.of() : acknowledged;
        List<String> missing = new ArrayList<>();
        for (String p : artifact.unsoundPrimitives()) {
            if (!ok.contains(p)) {
                missing.add(p);
            }
        }
        if (missing.isEmpty()) {
            return;
        }

        StringBuilder quoted = new StringBuilder();
        for (int i = 0; i < missing.size(); i++) {
            if (i > 0) quoted.append(", ");
            quoted.append('"').append(missing.get(i)).append('"');
        }
        String message = context
            + ": this artifact reaches " + missing.size() + " builtin"
            + (missing.size() == 1 ? "" : "s")
            + " the compiler does not claim is sound: " + String.join(", ", missing) + ". "
            + "The compiler emitted it only because the gap was acknowledged at COMPILE time; "
            + "funding it is a second decision, and this SDK will not make it for you. "
            + "Pass DeployOptions.withAcknowledgeUnsound(List.of(" + quoted + ")) to proceed";
        throw new UnsoundPrimitiveError(missing, context, message);
    }
}
