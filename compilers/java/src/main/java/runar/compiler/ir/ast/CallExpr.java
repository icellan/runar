package runar.compiler.ir.ast;

import java.util.List;

/**
 * A function or method call. The optional {@code asmReturnType} field is
 * set only for the expression form {@code asm<T>({...})} of the asm
 * compiler intrinsic and carries the captured primitive return type
 * ({@code "bigint"}, {@code "boolean"}, or {@code "ByteString"}). For
 * every non-asm call and for the statement form it is {@code null}.
 */
public record CallExpr(Expression callee, List<Expression> args, String asmReturnType)
    implements Expression {

    /** Construct a non-asm call (asmReturnType is null). */
    public CallExpr(Expression callee, List<Expression> args) {
        this(callee, args, null);
    }

    @Override
    public String kind() {
        return "call_expr";
    }
}
