package runar.compiler.ir.ast;

import java.util.List;

public record MethodNode(
    String name,
    List<ParamNode> params,
    List<Statement> body,
    Visibility visibility,
    SourceLocation sourceLocation
) {
    public String kind() {
        return "method";
    }
}
