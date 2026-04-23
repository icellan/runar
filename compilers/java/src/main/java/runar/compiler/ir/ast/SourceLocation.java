package runar.compiler.ir.ast;

public record SourceLocation(String file, int line, int column) {}
