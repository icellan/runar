package runar.compiler.ir.ast;

/** The base class a contract extends. */
public enum ParentClass {
    SMART_CONTRACT("SmartContract"),
    STATEFUL_SMART_CONTRACT("StatefulSmartContract");

    private final String canonical;

    ParentClass(String canonical) {
        this.canonical = canonical;
    }

    public String canonical() {
        return canonical;
    }

    public static ParentClass fromCanonical(String s) {
        for (ParentClass p : values()) {
            if (p.canonical.equals(s)) {
                return p;
            }
        }
        throw new IllegalArgumentException("unknown parent class: " + s);
    }
}
