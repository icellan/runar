package runar.compiler.frontend;

import com.sun.source.tree.AnnotationTree;
import com.sun.source.tree.ArrayAccessTree;
import com.sun.source.tree.AssignmentTree;
import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.BlockTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ConditionalExpressionTree;
import com.sun.source.tree.ExpressionStatementTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.ForLoopTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.IfTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.ModifiersTree;
import com.sun.source.tree.NewArrayTree;
import com.sun.source.tree.ParameterizedTypeTree;
import com.sun.source.tree.ParenthesizedTree;
import com.sun.source.tree.PrimitiveTypeTree;
import com.sun.source.tree.ReturnTree;
import com.sun.source.tree.StatementTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.UnaryTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.Trees;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import runar.compiler.ir.ast.ArrayLiteralExpr;
import runar.compiler.ir.ast.AssignmentStatement;
import runar.compiler.ir.ast.BigIntLiteral;
import runar.compiler.ir.ast.BinaryExpr;
import runar.compiler.ir.ast.BoolLiteral;
import runar.compiler.ir.ast.ByteStringLiteral;
import runar.compiler.ir.ast.CallExpr;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.ast.CustomType;
import runar.compiler.ir.ast.DecrementExpr;
import runar.compiler.ir.ast.Expression;
import runar.compiler.ir.ast.ExpressionStatement;
import runar.compiler.ir.ast.FixedArrayType;
import runar.compiler.ir.ast.ForStatement;
import runar.compiler.ir.ast.Identifier;
import runar.compiler.ir.ast.IfStatement;
import runar.compiler.ir.ast.IncrementExpr;
import runar.compiler.ir.ast.IndexAccessExpr;
import runar.compiler.ir.ast.MemberExpr;
import runar.compiler.ir.ast.MethodNode;
import runar.compiler.ir.ast.ParamNode;
import runar.compiler.ir.ast.ParentClass;
import runar.compiler.ir.ast.PrimitiveType;
import runar.compiler.ir.ast.PrimitiveTypeName;
import runar.compiler.ir.ast.PropertyAccessExpr;
import runar.compiler.ir.ast.PropertyNode;
import runar.compiler.ir.ast.ReturnStatement;
import runar.compiler.ir.ast.SourceLocation;
import runar.compiler.ir.ast.Statement;
import runar.compiler.ir.ast.TernaryExpr;
import runar.compiler.ir.ast.TypeNode;
import runar.compiler.ir.ast.UnaryExpr;
import runar.compiler.ir.ast.VariableDeclStatement;
import runar.compiler.ir.ast.Visibility;

/**
 * Parses {@code .runar.java} source into a Rúnar {@link ContractNode}.
 *
 * <p>Uses the standard-JDK {@code javax.tools.JavaCompiler} + {@code com.sun.source.tree}
 * API so no external parser dependency is required. The parser walks the
 * {@code CompilationUnitTree} produced by javac's parse phase and lowers
 * Java constructs to Rúnar AST nodes.
 *
 * <p><strong>Contract</strong>: the caller provides Java source containing
 * exactly one class declaration extending either {@link
 * runar.lang.SmartContract} or {@link runar.lang.StatefulSmartContract}.
 * Violations throw {@link ParseException}. Non-contract Java constructs
 * (inner classes, lambdas, switch expressions, generics beyond
 * {@code FixedArray}, try/catch, annotations other than {@code @Readonly}
 * / {@code @Public} / {@code @Stateful}) are rejected at parse time —
 * we prefer loud failures over silent divergence from other compilers.
 */
public final class JavaParser {

    private JavaParser() {}

    // ---------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------

    /** Parse Java source into a Rúnar contract AST. */
    public static ContractNode parse(String source, String filename) {
        CompilationUnitTree cu = parseToTree(source, filename);
        ClassTree classTree = firstTopLevelClass(cu, filename);
        return convertClass(classTree, filename, cu);
    }

    // ---------------------------------------------------------------
    // javac frontend invocation
    // ---------------------------------------------------------------

    private static CompilationUnitTree parseToTree(String source, String filename) {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new ParseException("no system Java compiler available — is this a JRE without tools.jar?");
        }
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        // Strip the Rúnar .runar. infix so the source filename (used by javac
        // for error messages and for SimpleJavaFileObject's URI-derived class
        // name) matches a plain Java convention. The Rúnar filename is
        // preserved separately for source-location reporting.
        JavaFileObject fileObject = new StringSource(stripRunarInfix(filename), source);
        JavacTask task = (JavacTask) compiler.getTask(
            null,
            null,
            diagnostics,
            List.of("-proc:none"),
            null,
            List.of(fileObject)
        );
        Iterable<? extends CompilationUnitTree> units;
        try {
            units = task.parse();
        } catch (IOException e) {
            throw new ParseException("I/O error parsing " + filename + ": " + e.getMessage());
        }
        List<String> errors = new ArrayList<>();
        for (var d : diagnostics.getDiagnostics()) {
            if (d.getKind() == Diagnostic.Kind.ERROR) {
                errors.add(d.getLineNumber() + ":" + d.getColumnNumber() + ": " + d.getMessage(null));
            }
        }
        if (!errors.isEmpty()) {
            throw new ParseException(
                "javac reported errors parsing " + filename + ":\n  " + String.join("\n  ", errors)
            );
        }
        var iter = units.iterator();
        if (!iter.hasNext()) {
            throw new ParseException("no compilation unit parsed from " + filename);
        }
        return iter.next();
    }

    private static String stripRunarInfix(String filename) {
        // "P2PKH.runar.java" -> "P2PKH.java"
        int dot = filename.lastIndexOf(".runar.");
        return dot < 0 ? filename : filename.substring(0, dot) + ".java";
    }

    private static ClassTree firstTopLevelClass(CompilationUnitTree cu, String filename) {
        for (Tree decl : cu.getTypeDecls()) {
            if (decl instanceof ClassTree ct) {
                return ct;
            }
        }
        throw new ParseException("no class declaration found in " + filename);
    }

    // ---------------------------------------------------------------
    // Class conversion
    // ---------------------------------------------------------------

    private static ContractNode convertClass(ClassTree cls, String filename, CompilationUnitTree cu) {
        ParentClass parentClass = determineParentClass(cls, filename);

        List<PropertyNode> properties = new ArrayList<>();
        MethodTree constructorTree = null;
        List<MethodTree> methodTrees = new ArrayList<>();

        String className = cls.getSimpleName().toString();

        for (Tree member : cls.getMembers()) {
            if (member instanceof VariableTree v) {
                properties.add(convertField(v, filename, cu));
            } else if (member instanceof MethodTree m) {
                if (m.getName().contentEquals("<init>") || m.getName().contentEquals(className)) {
                    if (constructorTree != null) {
                        throw new ParseException(className + " has more than one constructor");
                    }
                    constructorTree = m;
                } else {
                    methodTrees.add(m);
                }
            } else {
                throw new ParseException("unsupported class member: " + member.getKind() + " in " + className);
            }
        }

        MethodNode constructor = constructorTree != null
            ? convertMethod(constructorTree, filename, cu, className)
            : syntheticConstructor(properties, filename);

        List<MethodNode> methods = new ArrayList<>(methodTrees.size());
        for (MethodTree mt : methodTrees) {
            methods.add(convertMethod(mt, filename, cu, className));
        }

        return new ContractNode(className, parentClass, properties, constructor, methods, filename);
    }

    private static ParentClass determineParentClass(ClassTree cls, String filename) {
        Tree parent = cls.getExtendsClause();
        if (parent == null) {
            throw new ParseException("contract class in " + filename + " must extend SmartContract or StatefulSmartContract");
        }
        String name = typeSimpleName(parent);
        return switch (name) {
            case "SmartContract" -> ParentClass.SMART_CONTRACT;
            case "StatefulSmartContract" -> ParentClass.STATEFUL_SMART_CONTRACT;
            default -> throw new ParseException(
                "contract class in " + filename + " must extend SmartContract or StatefulSmartContract, got " + name
            );
        };
    }

    // ---------------------------------------------------------------
    // Field / property conversion
    // ---------------------------------------------------------------

    private static PropertyNode convertField(VariableTree v, String filename, CompilationUnitTree cu) {
        boolean readonly = hasAnnotation(v.getModifiers(), "Readonly");
        TypeNode type = convertType(v.getType(), filename);
        Expression init = v.getInitializer() != null ? convertExpression(v.getInitializer(), filename, cu) : null;
        return new PropertyNode(
            v.getName().toString(),
            type,
            readonly,
            init,
            locationOf(v, cu, filename),
            null
        );
    }

    // ---------------------------------------------------------------
    // Method conversion
    // ---------------------------------------------------------------

    private static MethodNode convertMethod(MethodTree m, String filename, CompilationUnitTree cu, String className) {
        boolean isConstructor = m.getName().contentEquals("<init>") || m.getName().contentEquals(className);

        Visibility vis;
        if (isConstructor) {
            vis = Visibility.PUBLIC;
        } else if (hasAnnotation(m.getModifiers(), "Public")) {
            vis = Visibility.PUBLIC;
        } else {
            vis = Visibility.PRIVATE;
        }

        List<ParamNode> params = new ArrayList<>(m.getParameters().size());
        for (VariableTree p : m.getParameters()) {
            params.add(new ParamNode(p.getName().toString(), convertType(p.getType(), filename)));
        }

        List<Statement> body = m.getBody() == null
            ? List.of()
            : convertStatements(m.getBody().getStatements(), filename, cu);

        String name = isConstructor ? "constructor" : m.getName().toString();
        return new MethodNode(name, params, body, vis, locationOf(m, cu, filename));
    }

    private static MethodNode syntheticConstructor(List<PropertyNode> properties, String filename) {
        List<ParamNode> params = new ArrayList<>();
        List<Statement> body = new ArrayList<>();
        SourceLocation loc = new SourceLocation(filename, 0, 0);

        // super(...) call
        List<Expression> superArgs = new ArrayList<>();
        for (PropertyNode p : properties) {
            if (p.initializer() != null) continue;
            params.add(new ParamNode(p.name(), p.type()));
            superArgs.add(new Identifier(p.name()));
        }
        body.add(new ExpressionStatement(
            new CallExpr(new Identifier("super"), superArgs),
            loc
        ));
        // this.x = x; for each constructor param
        for (PropertyNode p : properties) {
            if (p.initializer() != null) continue;
            body.add(new AssignmentStatement(
                new PropertyAccessExpr(p.name()),
                new Identifier(p.name()),
                loc
            ));
        }
        return new MethodNode("constructor", params, body, Visibility.PUBLIC, loc);
    }

    // ---------------------------------------------------------------
    // Type conversion
    // ---------------------------------------------------------------

    private static TypeNode convertType(Tree type, String filename) {
        if (type instanceof PrimitiveTypeTree pt) {
            return switch (pt.getPrimitiveTypeKind()) {
                case BOOLEAN -> new PrimitiveType(PrimitiveTypeName.BOOLEAN);
                case VOID -> throw new ParseException("void return type is unsupported (" + filename + ")");
                default -> throw new ParseException(
                    "unsupported primitive type " + pt.getPrimitiveTypeKind() + " in " + filename
                );
            };
        }
        if (type instanceof IdentifierTree id) {
            return resolveNamedType(id.getName().toString());
        }
        if (type instanceof MemberSelectTree ms) {
            return resolveNamedType(ms.getIdentifier().toString());
        }
        if (type instanceof ParameterizedTypeTree pt) {
            String name = typeSimpleName(pt.getType());
            if ("FixedArray".equals(name)) {
                if (pt.getTypeArguments().size() != 2) {
                    throw new ParseException("FixedArray requires 2 type arguments (element, length) in " + filename);
                }
                TypeNode element = convertType(pt.getTypeArguments().get(0), filename);
                Tree lenTree = pt.getTypeArguments().get(1);
                int length = parseFixedArrayLength(lenTree, filename);
                return new FixedArrayType(element, length);
            }
            throw new ParseException("unsupported generic type " + name + " in " + filename);
        }
        throw new ParseException("unsupported type node " + type.getKind() + " in " + filename);
    }

    private static TypeNode resolveNamedType(String name) {
        try {
            return new PrimitiveType(PrimitiveTypeName.fromCanonical(name));
        } catch (IllegalArgumentException unknown) {
            if ("Bigint".equals(name) || "BigInteger".equals(name)) {
                return new PrimitiveType(PrimitiveTypeName.BIGINT);
            }
            if ("Boolean".equals(name)) {
                return new PrimitiveType(PrimitiveTypeName.BOOLEAN);
            }
            if ("Ripemd160".equals(name) || "Hash160".equals(name)) {
                return new PrimitiveType(PrimitiveTypeName.RIPEMD_160);
            }
            return new CustomType(name);
        }
    }

    private static int parseFixedArrayLength(Tree lenTree, String filename) {
        if (lenTree instanceof LiteralTree lt && lt.getValue() instanceof Number n) {
            return n.intValue();
        }
        // Users cannot easily express integers as type arguments in Java;
        // FixedArray length is supplied via a nested static constant or
        // similar mechanism the compiler resolves during typecheck. For now
        // we require a literal.
        throw new ParseException("FixedArray length must be an integer literal in " + filename);
    }

    // ---------------------------------------------------------------
    // Statement conversion
    // ---------------------------------------------------------------

    private static List<Statement> convertStatements(List<? extends StatementTree> stmts, String filename, CompilationUnitTree cu) {
        List<Statement> out = new ArrayList<>(stmts.size());
        for (StatementTree s : stmts) {
            out.add(convertStatement(s, filename, cu));
        }
        return out;
    }

    private static Statement convertStatement(StatementTree s, String filename, CompilationUnitTree cu) {
        SourceLocation loc = locationOf(s, cu, filename);
        if (s instanceof VariableTree v) {
            TypeNode type = convertType(v.getType(), filename);
            Expression init = v.getInitializer() != null ? convertExpression(v.getInitializer(), filename, cu) : null;
            if (init == null) {
                throw new ParseException("local variable " + v.getName() + " must have an initializer in " + filename);
            }
            return new VariableDeclStatement(v.getName().toString(), type, init, loc);
        }
        if (s instanceof ExpressionStatementTree es) {
            ExpressionTree inner = es.getExpression();
            if (inner instanceof AssignmentTree at) {
                return new AssignmentStatement(
                    convertExpression(at.getVariable(), filename, cu),
                    convertExpression(at.getExpression(), filename, cu),
                    loc
                );
            }
            return new ExpressionStatement(convertExpression(inner, filename, cu), loc);
        }
        if (s instanceof IfTree it) {
            Expression cond = convertExpression(it.getCondition(), filename, cu);
            List<Statement> thenBody = flattenBlock(it.getThenStatement(), filename, cu);
            List<Statement> elseBody = it.getElseStatement() != null
                ? flattenBlock(it.getElseStatement(), filename, cu)
                : null;
            return new IfStatement(cond, thenBody, elseBody, loc);
        }
        if (s instanceof ForLoopTree fl) {
            if (fl.getInitializer().size() != 1 || !(fl.getInitializer().get(0) instanceof VariableTree initVar)) {
                throw new ParseException("for-loop must declare a single loop variable in " + filename);
            }
            if (fl.getUpdate().size() != 1) {
                throw new ParseException("for-loop must have a single update expression in " + filename);
            }
            VariableDeclStatement init = (VariableDeclStatement) convertStatement(initVar, filename, cu);
            Expression cond = convertExpression(fl.getCondition(), filename, cu);
            Statement update = convertStatement(fl.getUpdate().get(0), filename, cu);
            List<Statement> body = flattenBlock(fl.getStatement(), filename, cu);
            return new ForStatement(init, cond, update, body, loc);
        }
        if (s instanceof ReturnTree rt) {
            Expression value = rt.getExpression() != null ? convertExpression(rt.getExpression(), filename, cu) : null;
            return new ReturnStatement(value, loc);
        }
        if (s instanceof BlockTree bt) {
            // A bare block inside a block flattens.
            throw new ParseException("nested blocks are unsupported in " + filename + " (at " + loc.line() + ":" + loc.column() + ")");
        }
        throw new ParseException("unsupported statement kind " + s.getKind() + " in " + filename);
    }

    private static List<Statement> flattenBlock(StatementTree s, String filename, CompilationUnitTree cu) {
        if (s instanceof BlockTree bt) {
            return convertStatements(bt.getStatements(), filename, cu);
        }
        return List.of(convertStatement(s, filename, cu));
    }

    // ---------------------------------------------------------------
    // Expression conversion
    // ---------------------------------------------------------------

    private static Expression convertExpression(ExpressionTree e, String filename, CompilationUnitTree cu) {
        if (e instanceof ParenthesizedTree pt) {
            return convertExpression(pt.getExpression(), filename, cu);
        }
        if (e instanceof LiteralTree lt) {
            return convertLiteral(lt, filename);
        }
        if (e instanceof IdentifierTree id) {
            return new Identifier(id.getName().toString());
        }
        if (e instanceof MemberSelectTree ms) {
            // Special-case BigInteger.ZERO/ONE/TWO/TEN → literal. The Bigint
            // wrapper re-exports the same constants so both spellings are
            // accepted.
            if (ms.getExpression() instanceof IdentifierTree bi
                && (bi.getName().contentEquals("BigInteger") || bi.getName().contentEquals("Bigint"))) {
                return switch (ms.getIdentifier().toString()) {
                    case "ZERO" -> new BigIntLiteral(BigInteger.ZERO);
                    case "ONE" -> new BigIntLiteral(BigInteger.ONE);
                    case "TWO" -> new BigIntLiteral(BigInteger.TWO);
                    case "TEN" -> new BigIntLiteral(BigInteger.TEN);
                    default -> throw new ParseException(
                        "unsupported " + bi.getName() + " constant " + ms.getIdentifier() + " in " + filename
                    );
                };
            }
            // this.foo → PropertyAccessExpr("foo")
            if (ms.getExpression().getKind() == Tree.Kind.IDENTIFIER &&
                ((IdentifierTree) ms.getExpression()).getName().contentEquals("this")) {
                return new PropertyAccessExpr(ms.getIdentifier().toString());
            }
            return new MemberExpr(convertExpression(ms.getExpression(), filename, cu), ms.getIdentifier().toString());
        }
        if (e instanceof MethodInvocationTree mi) {
            return convertCall(mi, filename, cu);
        }
        if (e instanceof BinaryTree bt) {
            Expression.BinaryOp op = mapBinaryOp(bt.getKind(), filename);
            return new BinaryExpr(op,
                convertExpression(bt.getLeftOperand(), filename, cu),
                convertExpression(bt.getRightOperand(), filename, cu)
            );
        }
        if (e instanceof UnaryTree ut) {
            return convertUnary(ut, filename, cu);
        }
        if (e instanceof ConditionalExpressionTree ct) {
            return new TernaryExpr(
                convertExpression(ct.getCondition(), filename, cu),
                convertExpression(ct.getTrueExpression(), filename, cu),
                convertExpression(ct.getFalseExpression(), filename, cu)
            );
        }
        if (e instanceof ArrayAccessTree at) {
            return new IndexAccessExpr(
                convertExpression(at.getExpression(), filename, cu),
                convertExpression(at.getIndex(), filename, cu)
            );
        }
        if (e instanceof NewArrayTree na) {
            if (na.getInitializers() == null) {
                throw new ParseException("new-array expressions must have an initializer list in " + filename);
            }
            List<Expression> elements = new ArrayList<>(na.getInitializers().size());
            for (ExpressionTree el : na.getInitializers()) {
                elements.add(convertExpression(el, filename, cu));
            }
            return new ArrayLiteralExpr(elements);
        }
        if (e instanceof AssignmentTree at) {
            throw new ParseException(
                "assignments must be top-level statements, not expressions, in " + filename
            );
        }
        throw new ParseException("unsupported expression kind " + e.getKind() + " in " + filename);
    }

    private static Expression convertLiteral(LiteralTree lt, String filename) {
        Object value = lt.getValue();
        if (value == null) {
            throw new ParseException("null literals are unsupported in " + filename);
        }
        if (value instanceof Integer i) {
            return new BigIntLiteral(BigInteger.valueOf(i));
        }
        if (value instanceof Long l) {
            return new BigIntLiteral(BigInteger.valueOf(l));
        }
        if (value instanceof Boolean b) {
            return new BoolLiteral(b);
        }
        if (value instanceof String s) {
            // String literals in contract source are ByteString hex literals:
            //   ByteString.fromHex("deadbeef")  → covered by convertCall below
            // bare string literals are rejected here to avoid ambiguity.
            throw new ParseException(
                "bare String literals are not allowed in contracts; use ByteString.fromHex(\"...\") in " + filename
            );
        }
        if (value instanceof Character) {
            throw new ParseException("char literals are unsupported in " + filename);
        }
        if (value instanceof Double || value instanceof Float) {
            throw new ParseException("floating-point literals are unsupported in " + filename);
        }
        throw new ParseException("unsupported literal type " + value.getClass().getSimpleName() + " in " + filename);
    }

    private static Expression convertCall(MethodInvocationTree mi, String filename, CompilationUnitTree cu) {
        ExpressionTree callee = mi.getMethodSelect();
        // Recognise xxx.fromHex("deadbeef") → ByteStringLiteral.
        if (callee instanceof MemberSelectTree ms
            && ms.getIdentifier().contentEquals("fromHex")
            && mi.getArguments().size() == 1
            && mi.getArguments().get(0) instanceof LiteralTree hex
            && hex.getValue() instanceof String hs) {
            return new ByteStringLiteral(hs);
        }
        // Recognise BigInteger.valueOf(<int literal>) → BigIntLiteral, and
        // Bigint.of(<int literal>) as the equivalent shorthand on the Bigint
        // wrapper.
        if (callee instanceof MemberSelectTree ms
            && ms.getExpression() instanceof IdentifierTree bi
            && ((bi.getName().contentEquals("BigInteger") && ms.getIdentifier().contentEquals("valueOf"))
                || (bi.getName().contentEquals("Bigint") && ms.getIdentifier().contentEquals("of")))
            && mi.getArguments().size() == 1
            && mi.getArguments().get(0) instanceof LiteralTree n
            && n.getValue() instanceof Number num) {
            return new BigIntLiteral(BigInteger.valueOf(num.longValue()));
        }
        // Bigint.of(<arbitrary expression>) — wrapping a BigInteger-typed value
        // (e.g. the result of a builtin like `percentOf` or `extractLocktime`)
        // into a Bigint. At the Rúnar AST level Bigint and BigInteger collapse
        // to the same BIGINT primitive, so the wrap is a no-op: lower to the
        // inner expression. Mirrors how BigInteger.valueOf(<non-literal>) would
        // also collapse (the JDK valueOf is identity at this layer).
        if (callee instanceof MemberSelectTree ms
            && ms.getExpression() instanceof IdentifierTree bi
            && ((bi.getName().contentEquals("Bigint") && ms.getIdentifier().contentEquals("of"))
                || (bi.getName().contentEquals("BigInteger") && ms.getIdentifier().contentEquals("valueOf")))
            && mi.getArguments().size() == 1) {
            return convertExpression(mi.getArguments().get(0), filename, cu);
        }
        // <bigint>.value() — unwrapping a Bigint back to its underlying
        // BigInteger. Symmetric no-op to Bigint.of(...) above.
        if (callee instanceof MemberSelectTree ms
            && ms.getIdentifier().contentEquals("value")
            && mi.getArguments().isEmpty()) {
            return convertExpression(ms.getExpression(), filename, cu);
        }
        // Recognise super(...) inside the constructor.
        if (callee instanceof IdentifierTree id && id.getName().contentEquals("super")) {
            List<Expression> args = convertArgs(mi, filename, cu);
            return new CallExpr(new Identifier("super"), args);
        }
        // Recognise Bigint-wrapper arithmetic: a.plus(b) → BinaryExpr(ADD, a, b),
        // a.neg() → UnaryExpr(NEG, a), etc. Matched by method name and arity;
        // the receiver type is not consulted (the parser has no type info at
        // this stage), so non-Bigint receivers with identically-named methods
        // would also be lowered. In practice contract source calls these only
        // on Bigint values, and the typechecker will catch misuse.
        Optional<Expression> lowered = tryLowerBigintMethod(mi, filename, cu);
        if (lowered.isPresent()) {
            return lowered.get();
        }
        // General call: callee = expression, args = list.
        Expression calleeExpr = convertExpression(callee, filename, cu);
        List<Expression> args = convertArgs(mi, filename, cu);
        return new CallExpr(calleeExpr, args);
    }

    /**
     * Lower {@code Bigint}-wrapper method calls to their canonical AST
     * arithmetic form, so contract source written in {@code a.plus(b)} style
     * compiles identically to source written as {@code a + b}.
     *
     * <p>Recognised method names:
     * <ul>
     *   <li>binary arithmetic: {@code plus}, {@code minus}, {@code times},
     *       {@code div}, {@code mod}, {@code shl}, {@code shr},
     *       {@code and}, {@code or}, {@code xor}</li>
     *   <li>binary comparison: {@code gt}, {@code lt}, {@code ge},
     *       {@code le}, {@code eq}, {@code neq}</li>
     *   <li>unary: {@code neg}, {@code abs}</li>
     * </ul>
     *
     * <p>Returns {@link Optional#empty()} if the call does not match the
     * Bigint-method pattern (wrong callee shape, wrong arity, or unknown
     * method name); callers fall back to the general call lowering.
     */
    private static Optional<Expression> tryLowerBigintMethod(
        MethodInvocationTree mi,
        String filename,
        CompilationUnitTree cu
    ) {
        ExpressionTree callee = mi.getMethodSelect();
        if (!(callee instanceof MemberSelectTree ms)) return Optional.empty();
        String method = ms.getIdentifier().toString();

        Expression.BinaryOp binOp = BIGINT_BINARY_METHODS.get(method);
        if (binOp != null) {
            if (mi.getArguments().size() != 1) return Optional.empty();
            Expression receiver = convertExpression(ms.getExpression(), filename, cu);
            Expression arg = convertExpression(mi.getArguments().get(0), filename, cu);
            return Optional.of(new BinaryExpr(binOp, receiver, arg));
        }

        if ("neg".equals(method) && mi.getArguments().isEmpty()) {
            Expression receiver = convertExpression(ms.getExpression(), filename, cu);
            return Optional.of(new UnaryExpr(Expression.UnaryOp.NEG, receiver));
        }
        if ("abs".equals(method) && mi.getArguments().isEmpty()) {
            // abs is a Rúnar builtin, not an operator: lower to CallExpr(abs, a).
            Expression receiver = convertExpression(ms.getExpression(), filename, cu);
            return Optional.of(new CallExpr(new Identifier("abs"), List.of(receiver)));
        }

        return Optional.empty();
    }

    /** Bigint method-name → canonical BinaryOp table (unary ops handled separately). */
    private static final Map<String, Expression.BinaryOp> BIGINT_BINARY_METHODS = Map.ofEntries(
        Map.entry("plus",  Expression.BinaryOp.ADD),
        Map.entry("minus", Expression.BinaryOp.SUB),
        Map.entry("times", Expression.BinaryOp.MUL),
        Map.entry("div",   Expression.BinaryOp.DIV),
        Map.entry("mod",   Expression.BinaryOp.MOD),
        Map.entry("shl",   Expression.BinaryOp.SHL),
        Map.entry("shr",   Expression.BinaryOp.SHR),
        Map.entry("and",   Expression.BinaryOp.BIT_AND),
        Map.entry("or",    Expression.BinaryOp.BIT_OR),
        Map.entry("xor",   Expression.BinaryOp.BIT_XOR),
        Map.entry("gt",    Expression.BinaryOp.GT),
        Map.entry("lt",    Expression.BinaryOp.LT),
        Map.entry("ge",    Expression.BinaryOp.GE),
        Map.entry("le",    Expression.BinaryOp.LE),
        Map.entry("eq",    Expression.BinaryOp.EQ),
        Map.entry("neq",   Expression.BinaryOp.NEQ)
    );

    private static List<Expression> convertArgs(MethodInvocationTree mi, String filename, CompilationUnitTree cu) {
        List<Expression> args = new ArrayList<>(mi.getArguments().size());
        for (ExpressionTree arg : mi.getArguments()) {
            args.add(convertExpression(arg, filename, cu));
        }
        return args;
    }

    private static Expression.BinaryOp mapBinaryOp(Tree.Kind kind, String filename) {
        return switch (kind) {
            case PLUS -> Expression.BinaryOp.ADD;
            case MINUS -> Expression.BinaryOp.SUB;
            case MULTIPLY -> Expression.BinaryOp.MUL;
            case DIVIDE -> Expression.BinaryOp.DIV;
            case REMAINDER -> Expression.BinaryOp.MOD;
            case EQUAL_TO -> Expression.BinaryOp.EQ;
            case NOT_EQUAL_TO -> Expression.BinaryOp.NEQ;
            case LESS_THAN -> Expression.BinaryOp.LT;
            case LESS_THAN_EQUAL -> Expression.BinaryOp.LE;
            case GREATER_THAN -> Expression.BinaryOp.GT;
            case GREATER_THAN_EQUAL -> Expression.BinaryOp.GE;
            case CONDITIONAL_AND -> Expression.BinaryOp.AND;
            case CONDITIONAL_OR -> Expression.BinaryOp.OR;
            case AND -> Expression.BinaryOp.BIT_AND;
            case OR -> Expression.BinaryOp.BIT_OR;
            case XOR -> Expression.BinaryOp.BIT_XOR;
            case LEFT_SHIFT -> Expression.BinaryOp.SHL;
            case RIGHT_SHIFT -> Expression.BinaryOp.SHR;
            default -> throw new ParseException("unsupported binary operator " + kind + " in " + filename);
        };
    }

    private static Expression convertUnary(UnaryTree ut, String filename, CompilationUnitTree cu) {
        Expression operand = convertExpression(ut.getExpression(), filename, cu);
        return switch (ut.getKind()) {
            case LOGICAL_COMPLEMENT -> new UnaryExpr(Expression.UnaryOp.NOT, operand);
            case UNARY_MINUS -> new UnaryExpr(Expression.UnaryOp.NEG, operand);
            case BITWISE_COMPLEMENT -> new UnaryExpr(Expression.UnaryOp.BIT_NOT, operand);
            case UNARY_PLUS -> operand; // +x == x
            case PREFIX_INCREMENT -> new IncrementExpr(operand, true);
            case POSTFIX_INCREMENT -> new IncrementExpr(operand, false);
            case PREFIX_DECREMENT -> new DecrementExpr(operand, true);
            case POSTFIX_DECREMENT -> new DecrementExpr(operand, false);
            default -> throw new ParseException("unsupported unary operator " + ut.getKind() + " in " + filename);
        };
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private static boolean hasAnnotation(ModifiersTree mods, String simpleName) {
        if (mods == null) return false;
        for (AnnotationTree a : mods.getAnnotations()) {
            if (typeSimpleName(a.getAnnotationType()).equals(simpleName)) {
                return true;
            }
        }
        return false;
    }

    private static String typeSimpleName(Tree t) {
        if (t instanceof IdentifierTree id) return id.getName().toString();
        if (t instanceof MemberSelectTree ms) return ms.getIdentifier().toString();
        if (t instanceof ParameterizedTypeTree pt) return typeSimpleName(pt.getType());
        return t.toString();
    }

    private static SourceLocation locationOf(Tree t, CompilationUnitTree cu, String filename) {
        // Trees has a SourcePositions helper, but it needs a Trees
        // instance bound to the JavacTask. We don't have one at this
        // point — the parser returns only the tree. Source locations at
        // this pass are approximate (line 0, column 0); the AST loses
        // precision here. A future pass can re-attach locations by
        // tracking line breaks in the source string.
        return new SourceLocation(filename, 0, 0);
    }

    // ---------------------------------------------------------------
    // javax.tools adapters
    // ---------------------------------------------------------------

    private static final class StringSource extends SimpleJavaFileObject {
        private final String content;

        StringSource(String name, String content) {
            super(URI.create("mem:///" + name), Kind.SOURCE);
            this.content = content;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return content;
        }
    }

    /** Unchecked exception for parse-time problems. */
    public static final class ParseException extends RuntimeException {
        public ParseException(String message) {
            super(message);
        }
    }
}
