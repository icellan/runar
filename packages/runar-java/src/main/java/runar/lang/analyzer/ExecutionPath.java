package runar.lang.analyzer;

import java.util.List;

/**
 * One enumerated spending path through the script's IF/ELSE control flow.
 * See spec §3.3 / §7.
 */
public final class ExecutionPath {
    public final int id;
    public final String description;
    public final List<Boolean> branchChoices;
    public final boolean reachable;
    public final boolean hasCheckSig;
    public final int stackDepthAtEnd;

    public ExecutionPath(int id, String description, List<Boolean> branchChoices,
                         boolean reachable, boolean hasCheckSig, int stackDepthAtEnd) {
        this.id = id;
        this.description = description;
        this.branchChoices = List.copyOf(branchChoices);
        this.reachable = reachable;
        this.hasCheckSig = hasCheckSig;
        this.stackDepthAtEnd = stackDepthAtEnd;
    }
}
