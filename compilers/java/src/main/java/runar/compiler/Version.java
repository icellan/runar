package runar.compiler;

/**
 * Runar Java compiler version. Kept in sync with the root package.json
 * version and every other language's SDK version; bumped together via
 * the repo-wide bump-version script.
 */
public final class Version {
    private Version() {}

    public static final String VALUE = "0.4.4";
}
