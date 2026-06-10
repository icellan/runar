package runar.lang.analyzer;

/** Top-level summary block per spec §3.4. */
public final class Summary {
    public final int totalPaths;
    public final int reachablePaths;
    public final int pathsWithCheckSig;
    public final int pathsWithoutCheckSig;
    public final int maxStackDepth;
    public final int scriptSizeBytes;

    public Summary(int totalPaths, int reachablePaths, int pathsWithCheckSig,
                   int pathsWithoutCheckSig, int maxStackDepth, int scriptSizeBytes) {
        this.totalPaths = totalPaths;
        this.reachablePaths = reachablePaths;
        this.pathsWithCheckSig = pathsWithCheckSig;
        this.pathsWithoutCheckSig = pathsWithoutCheckSig;
        this.maxStackDepth = maxStackDepth;
        this.scriptSizeBytes = scriptSizeBytes;
    }
}
