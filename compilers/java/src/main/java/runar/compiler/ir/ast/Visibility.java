package runar.compiler.ir.ast;

public enum Visibility {
    PUBLIC("public"),
    PRIVATE("private");

    private final String canonical;

    Visibility(String canonical) {
        this.canonical = canonical;
    }

    public String canonical() {
        return canonical;
    }
}
