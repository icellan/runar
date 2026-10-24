package runar.compiler.frontend;

import com.sun.source.tree.AnnotationTree;
import com.sun.source.tree.ArrayAccessTree;
import com.sun.source.tree.AssignmentTree;
import com.sun.source.tree.BinaryTree;
import com.sun.source.tree.BlockTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.CompoundAssignmentTree;
import com.sun.source.tree.ConditionalExpressionTree;
import com.sun.source.tree.EmptyStatementTree;
import com.sun.source.tree.ExpressionStatementTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.ForLoopTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.IfTree;
import com.sun.source.tree.LineMap;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.ModifiersTree;
import com.sun.source.tree.NewArrayTree;
import com.sun.source.tree.NewClassTree;
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
import runar.compiler.passes.SighashDirective;

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
        // DoS-bound size guard, enforced at every exported parser entry, not
        // just ParserDispatch.parse. N-136.
        try {
            InputLimits.assertSourceBytesUnderLimit(source);
        } catch (ParserDispatch.ParseException e) {
            throw new ParseException(e.getMessage());
        }
        // F-213: measure (A) is recomputed over javac's tree (javac's parser
        // cannot be instrumented) BEFORE the converter recurses into it;
        // measure (B) runs on the converted contract. A StackOverflowError
        // from javac itself or from the converter on a loop-built chain far
        // past the limit is the backstop (SourceNesting.guard).
        return SourceNesting.guard(() -> {
            Unit unit = parseToTree(source, filename);
            if (parseNestingViolation(unit.cu()) != null) throw new SourceNesting.LimitExceeded();
            ClassTree classTree = firstTopLevelClass(unit.cu(), filename);
            return convertClass(classTree, filename, unit);
        }, ParseException::new);
    }

    // ---------------------------------------------------------------
    // javac frontend invocation
    // ---------------------------------------------------------------

    /**
     * A parsed compilation unit paired with the {@link SourcePositions}
     * helper bound to the {@link JavacTask} that produced it. Both halves
     * are needed to resolve a {@link Tree} to a (line, column) pair:
     * {@code positions} maps a tree to a character offset, and the unit's
     * {@link LineMap} maps that offset to line/column. The task is local
     * to {@link #parseToTree}, so the pair is threaded through the
     * converters instead of the bare {@code CompilationUnitTree}.
     */
    private record Unit(CompilationUnitTree cu, SourcePositions positions) {}

    private static Unit parseToTree(String source, String filename) {
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
        // F-213: javac's own output (its "An exception has occurred in the
        // compiler" banner on a stack overflow) is not this compiler's
        // diagnostic; diagnostics proper go through the collector.
        java.io.StringWriter javacOut = new java.io.StringWriter();
        JavacTask task = (JavacTask) compiler.getTask(
            javacOut,
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
        } catch (RuntimeException e) {
            // F-213: javac wraps a StackOverflowError in its own parser (a
            // source nested thousands deep) in a RuntimeException.
            for (Throwable c = e; c != null; c = c.getCause()) {
                if (c instanceof StackOverflowError) throw new SourceNesting.LimitExceeded();
            }
            throw e;
        }
        List<String> errors = new ArrayList<>();
        for (var d : diagnostics.getDiagnostics()) {
            if (d.getKind() == Diagnostic.Kind.ERROR) {
                // F-026: javac's error on a malformed integer literal also
                // gets the shared text every other tier emits for it.
                String shared = sharedLiteralDiagnostic(source, (int) d.getPosition());
                String where = javacDiagnosticLocation(source, filename, d);
                if (shared != null) errors.add(where + shared);
                // N-214: javac's "illegal character: '\u00a7'" is the TS
                // reference's "Unexpected character '§'", at the same position.
                long p = d.getPosition();
                if ("compiler.err.illegal.char".equals(d.getCode()) && p >= 0 && p < source.length()) {
                    errors.add(where + "Unexpected character '" + source.charAt((int) p) + "'");
                } else {
                    errors.add(where + d.getMessage(null));
                }
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
        return new Unit(iter.next(), Trees.instance(task).getSourcePositions());
    }

    /**
     * F-026: when javac reports an error inside a number token (the run of
     * {@code [0-9A-Za-z_]} starting at a digit that contains {@code pos}), the
     * shared refusal of that literal. javac has already judged the context, so a
     * literal valid only under a unary minus counts as refused here.
     */
    private static String sharedLiteralDiagnostic(String source, int pos) {
        if (pos < 0 || pos >= source.length() || !IntLiteral.isNumberContinue(source.charAt(pos))) return null;
        int start = pos;
        while (start > 0 && IntLiteral.isNumberContinue(source.charAt(start - 1))) start--;
        char first = source.charAt(start);
        if (first < '0' || first > '9') return null;
        String text = source.substring(start, IntLiteral.scanEnd(source, start));
        IntLiteral.Lit lit = IntLiteral.parse("java", text);
        if (lit != null && !lit.negOnly()) return null;
        return IntLiteral.invalid("java", text);
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

    private static ContractNode convertClass(ClassTree cls, String filename, Unit cu) {
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
                    // N-050: a static method is not a contract method
                    // (`@Public static` used to become a spending entry point).
                    if (m.getModifiers().getFlags().contains(javax.lang.model.element.Modifier.STATIC)) {
                        throw new ParseException(LexDiag.staticMethod(m.getName().toString()));
                    }
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

        checkBarePropertyAssignments(properties, constructor, methods);
        return new ContractNode(className, parentClass, properties, constructor, methods, filename);
    }

    // ---------------------------------------------------------------
    // N-023 (R49): bare property assignment
    // ---------------------------------------------------------------

    /**
     * In Java a bare name inside a method that no local or parameter shadows
     * IS the field, so {@code count = ...}, {@code count++} and
     * {@code --count} write contract state. Lowering them as a local rebind
     * dropped the state write silently, so the bare form is refused (mirrors
     * the TS reference's checkBarePropertyAssignments). Shadowing follows
     * Java block scope: parameters, a local from its declaration to the end
     * of its block, a for-loop variable inside the loop. Bare reads are not
     * touched. (Compound {@code op=} never reaches here: this tier refuses
     * every compound assignment during conversion.)
     */
    private static void checkBarePropertyAssignments(
        List<PropertyNode> properties, MethodNode constructor, List<MethodNode> methods
    ) {
        Set<String> props = new HashSet<>();
        for (PropertyNode p : properties) props.add(p.name());
        if (props.isEmpty()) return;
        List<MethodNode> all = new ArrayList<>();
        all.add(constructor);
        all.addAll(methods);
        for (MethodNode m : all) {
            List<Set<String>> scope = new ArrayList<>();
            Set<String> params = new HashSet<>();
            for (ParamNode p : m.params()) params.add(p.name());
            scope.add(params);
            bareBlock(m.body(), scope, props);
        }
    }

    private static void bareTarget(Expression e, List<Set<String>> scope, Set<String> props) {
        if (e instanceof Identifier id && props.contains(id.name())) {
            for (Set<String> s : scope) {
                if (s.contains(id.name())) return;
            }
            throw new ParseException(LexDiag.bareJavaPropertyAssignment(id.name()));
        }
    }

    private static void bareBlock(List<Statement> body, List<Set<String>> outer, Set<String> props) {
        if (body == null) return;
        List<Set<String>> scope = new ArrayList<>(outer);
        scope.add(new HashSet<>());
        for (Statement s : body) bareStmt(s, scope, props);
    }

    private static void bareStmt(Statement s, List<Set<String>> scope, Set<String> props) {
        if (s instanceof VariableDeclStatement v) {
            bareExpr(v.init(), scope, props);
            scope.get(scope.size() - 1).add(v.name());
        } else if (s instanceof AssignmentStatement a) {
            bareTarget(a.target(), scope, props);
            bareExpr(a.target(), scope, props);
            bareExpr(a.value(), scope, props);
        } else if (s instanceof IfStatement i) {
            bareExpr(i.condition(), scope, props);
            bareBlock(i.thenBody(), scope, props);
            bareBlock(i.elseBody(), scope, props);
        } else if (s instanceof ForStatement f) {
            List<Set<String>> loop = new ArrayList<>(scope);
            loop.add(new HashSet<>());
            if (f.init() != null) bareStmt(f.init(), loop, props);
            bareExpr(f.condition(), loop, props);
            if (f.update() != null) bareStmt(f.update(), loop, props);
            bareBlock(f.body(), loop, props);
        } else if (s instanceof ReturnStatement r) {
            bareExpr(r.value(), scope, props);
        } else if (s instanceof ExpressionStatement es) {
            bareExpr(es.expression(), scope, props);
        }
    }

    private static void bareExpr(Expression e, List<Set<String>> scope, Set<String> props) {
        if (e == null) return;
        if (e instanceof IncrementExpr x) {
            bareTarget(x.operand(), scope, props);
            bareExpr(x.operand(), scope, props);
        } else if (e instanceof DecrementExpr x) {
            bareTarget(x.operand(), scope, props);
            bareExpr(x.operand(), scope, props);
        } else if (e instanceof BinaryExpr x) {
            bareExpr(x.left(), scope, props);
            bareExpr(x.right(), scope, props);
        } else if (e instanceof UnaryExpr x) {
            bareExpr(x.operand(), scope, props);
        } else if (e instanceof CallExpr x) {
            bareExpr(x.callee(), scope, props);
            for (Expression a : x.args()) bareExpr(a, scope, props);
        } else if (e instanceof MemberExpr x) {
            bareExpr(x.object(), scope, props);
        } else if (e instanceof TernaryExpr x) {
            bareExpr(x.condition(), scope, props);
            bareExpr(x.consequent(), scope, props);
            bareExpr(x.alternate(), scope, props);
        } else if (e instanceof IndexAccessExpr x) {
            bareExpr(x.object(), scope, props);
            bareExpr(x.index(), scope, props);
        } else if (e instanceof ArrayLiteralExpr x) {
            for (Expression el : x.elements()) bareExpr(el, scope, props);
        }
    }

    private static ParentClass determineParentClass(ClassTree cls, String filename) {
        Tree parent = cls.getExtendsClause();
        if (parent == null) {
            throw new ParseException(
                "contract class in " + filename
                    + " must extend SmartContract, StatefulSmartContract, or UnsafeSmartContract"
            );
        }
        String name = typeSimpleName(parent);
        return switch (name) {
            case "SmartContract" -> ParentClass.SMART_CONTRACT;
            case "StatefulSmartContract" -> ParentClass.STATEFUL_SMART_CONTRACT;
            case "UnsafeSmartContract" -> ParentClass.UNSAFE_SMART_CONTRACT;
            default -> throw new ParseException(
                "contract class in " + filename
                    + " must extend SmartContract, StatefulSmartContract, or UnsafeSmartContract, got " + name
            );
        };
    }

    // ---------------------------------------------------------------
    // Field / property conversion
    // ---------------------------------------------------------------

    private static PropertyNode convertField(VariableTree v, String filename, Unit cu) {
        validateAnnotations(v.getModifiers());
        boolean readonly = hasAnnotation(v.getModifiers(), "Readonly");
        // N-093: `@EmbedAlways` is the native spelling of the `@embedAlways`
        // directive; a `@Sighash` here annotates nothing.
        boolean embedAlways = hasAnnotation(v.getModifiers(), "EmbedAlways");
        if (hasAnnotation(v.getModifiers(), "Sighash")) {
            throw new ParseException(SighashDirective.lostDirectiveMessage("@sighash"));
        }
        TypeNode type = convertType(v.getType(), filename);
        Expression init = v.getInitializer() != null ? convertExpression(v.getInitializer(), filename, cu) : null;
        return new PropertyNode(
            v.getName().toString(),
            type,
            readonly,
            init,
            locationOf(v, cu, filename),
            null,
            embedAlways
        );
    }

    // ---------------------------------------------------------------
    // Method conversion
    // ---------------------------------------------------------------

    private static MethodNode convertMethod(MethodTree m, String filename, Unit cu, String className) {
        validateAnnotations(m.getModifiers());
        boolean isConstructor = m.getName().contentEquals("<init>") || m.getName().contentEquals(className);

        // N-093: `@EmbedAlways` / `@Sighash("FLAGS")`, the native spellings of
        // the `@embedAlways` / `@sighash` directives. Neither applies to the
        // constructor (not a spending entry point, not a field), nor
        // `@EmbedAlways` to any method. Checked in the TS reference's order.
        boolean sighashAnn = hasAnnotation(m.getModifiers(), "Sighash");
        boolean embedAnn = hasAnnotation(m.getModifiers(), "EmbedAlways");
        if (isConstructor && sighashAnn) {
            throw new ParseException(SighashDirective.lostDirectiveMessage("@sighash"));
        }
        if (embedAnn) {
            throw new ParseException(SighashDirective.lostDirectiveMessage("@embedAlways"));
        }

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

        // The AST keeps no return type; N-331 refuses an unknown name. A
        // primitive return type (`void`, `boolean`) is not a name to check.
        // N-332: a public method may declare no return type but `void`.
        if (!isConstructor && m.getReturnType() != null) {
            if (m.getReturnType() instanceof PrimitiveTypeTree ptt) {
                if (vis == Visibility.PUBLIC && ptt.getPrimitiveTypeKind() != javax.lang.model.type.TypeKind.VOID) {
                    throw new ParseException(LexDiag.publicReturnType(m.getName().toString()));
                }
            } else {
                String unknownReturn = LexDiag.unknownReturnType(
                    convertType(m.getReturnType(), filename), m.getName().toString(), vis == Visibility.PUBLIC);
                if (unknownReturn != null) {
                    throw new ParseException(unknownReturn);
                }
            }
        }

        List<Statement> body = m.getBody() == null
            ? List.of()
            : convertStatements(m.getBody().getStatements(), filename, cu);

        String name = isConstructor ? "constructor" : m.getName().toString();
        SighashDirective.Result sighash = isConstructor
            ? null
            : SighashDirective.resolveNativeSighash(name, vis == Visibility.PUBLIC, sighashSpecs(m.getModifiers()));
        if (sighash != null && sighash.isError()) {
            throw new ParseException(sighash.error());
        }
        return new MethodNode(name, params, body, vis, locationOf(m, cu, filename),
            sighash == null ? null : sighash.value());
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
            // N-108: `docs/formats/java.md` publishes `Sha256Digest -> Sha256`
            // in the Java surface type table and ships
            // `runar.lang.types.Sha256Digest` as an importable type, so
            // contracts written against the documentation spell it. This tier
            // resolved the alias in its OTHER six surface parsers (TsParser,
            // GoParser, RustParser, PyParser, RbParser, ZigParser) and refused
            // it on its own -- a compiler rejecting the name its own format
            // guide documents. Gate:
            // conformance/subtype-parity/Sha256DigestAliasJava.runar.java.
            if ("Sha256Digest".equals(name)) {
                return new PrimitiveType(PrimitiveTypeName.SHA_256);
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

    private static List<Statement> convertStatements(List<? extends StatementTree> stmts, String filename, Unit cu) {
        List<Statement> out = new ArrayList<>(stmts.size());
        for (StatementTree s : stmts) {
            // N-053: an empty statement `;` is a no-op, as in the TS reference.
            if (s instanceof EmptyStatementTree) continue;
            out.add(convertStatement(s, filename, cu));
        }
        return out;
    }

    private static Statement convertStatement(StatementTree s, String filename, Unit cu) {
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
            if (inner instanceof CompoundAssignmentTree ct) {
                // `t op= e` lowers to `t = t op e`, like the TS reference
                // (01-parse-java.ts finishExpressionStatement).
                Expression.BinaryOp op = mapCompoundOp(ct.getKind(), filename);
                Expression target = convertExpression(ct.getVariable(), filename, cu);
                return new AssignmentStatement(
                    target,
                    new BinaryExpr(op, target, convertExpression(ct.getExpression(), filename, cu)),
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

    private static List<Statement> flattenBlock(StatementTree s, String filename, Unit cu) {
        if (s instanceof BlockTree bt) {
            return convertStatements(bt.getStatements(), filename, cu);
        }
        if (s instanceof EmptyStatementTree) return List.of(); // N-053: `if (c) ;`
        return List.of(convertStatement(s, filename, cu));
    }

    // ---------------------------------------------------------------
    // Expression conversion
    // ---------------------------------------------------------------

    private static Expression convertExpression(ExpressionTree e, String filename, Unit cu) {
        if (e instanceof ParenthesizedTree pt) {
            return convertExpression(pt.getExpression(), filename, cu);
        }
        if (e instanceof LiteralTree lt) {
            return convertLiteral(lt, filename, cu);
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
            // Fold `<a>.compareTo(<b>) <cmp> 0` → `<a> <cmp> <b>`. Java's
            // BigInteger.compareTo returns -1/0/1, so the comparison-against-
            // zero idiom is the standard Java spelling for ordered comparison
            // on BigInteger. We rewrite at parse time so the canonical Rúnar
            // AST sees a single BinaryExpr — avoiding a redundant SUB and
            // matching the IR produced by `<a> <cmp> <b>` in other formats.
            // The fold only triggers when the right operand is the literal 0
            // and the operator is one of the six comparison ops; any other
            // shape leaves compareTo as an Unknown call (which the typechecker
            // will reject loudly).
            if (isComparisonOp(op)
                && bt.getRightOperand() instanceof LiteralTree zeroLit
                && zeroLit.getValue() instanceof Number zn
                && zn.longValue() == 0L
                && bt.getLeftOperand() instanceof MethodInvocationTree leftMi
                && leftMi.getMethodSelect() instanceof MemberSelectTree leftMs
                && leftMs.getIdentifier().contentEquals("compareTo")
                && leftMi.getArguments().size() == 1) {
                Expression a = convertExpression(leftMs.getExpression(), filename, cu);
                Expression b = convertExpression(leftMi.getArguments().get(0), filename, cu);
                return new BinaryExpr(op, a, b);
            }
            // Symmetric: `0 <cmp> <a>.compareTo(<b>)` → `<b> <cmp> <a>`.
            if (isComparisonOp(op)
                && bt.getLeftOperand() instanceof LiteralTree zeroLit2
                && zeroLit2.getValue() instanceof Number zn2
                && zn2.longValue() == 0L
                && bt.getRightOperand() instanceof MethodInvocationTree rightMi
                && rightMi.getMethodSelect() instanceof MemberSelectTree rightMs
                && rightMs.getIdentifier().contentEquals("compareTo")
                && rightMi.getArguments().size() == 1) {
                Expression a = convertExpression(rightMs.getExpression(), filename, cu);
                Expression b = convertExpression(rightMi.getArguments().get(0), filename, cu);
                return new BinaryExpr(op, b, a);
            }
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
        if (e instanceof NewClassTree nc) {
            // `new BigInteger("decimalstring")` / `new BigInteger("hex", 16)` —
            // escape hatch for bigint constants whose magnitude exceeds
            // Long.MAX_VALUE. The BigInteger.valueOf(...) path only handles
            // values that fit in a `long` because the JDK factory's signature
            // is `valueOf(long)`; for the secp256k1 group order (256 bits)
            // there is no other way to express the constant in Java source
            // that still compiles under javac. Folded into a BigIntLiteral at
            // parse time; emits the same ANF as a TS `0xFF...n` literal.
            ExpressionTree identTree = nc.getIdentifier();
            String typeName = null;
            if (identTree instanceof IdentifierTree it) {
                typeName = it.getName().toString();
            } else if (identTree instanceof MemberSelectTree ms) {
                typeName = ms.getIdentifier().toString();
            }
            if ("BigInteger".equals(typeName) && !nc.getArguments().isEmpty()
                && nc.getArguments().get(0) instanceof LiteralTree litTree
                && litTree.getValue() instanceof String decStr) {
                int radix = 10;
                if (nc.getArguments().size() >= 2
                    && nc.getArguments().get(1) instanceof LiteralTree radixLit
                    && radixLit.getValue() instanceof Number radixNum) {
                    radix = radixNum.intValue();
                }
                try {
                    return new BigIntLiteral(new BigInteger(decStr, radix));
                } catch (NumberFormatException nfe) {
                    throw new ParseException(
                        "cannot parse `new BigInteger(\"" + decStr + "\", " + radix + ")` in " + filename
                        + ": " + nfe.getMessage()
                    );
                }
            }
            throw new ParseException(
                "`new` is only supported for array literals (new T[]{...}) and `new BigInteger(\"...\")` literals in " + filename
            );
        }
        if (e instanceof AssignmentTree at) {
            throw new ParseException(
                "assignments must be top-level statements, not expressions, in " + filename
            );
        }
        throw new ParseException("unsupported expression kind " + e.getKind() + " in " + filename);
    }

    /**
     * F-189: javac's parser folds a minus in front of a decimal integer literal
     * into the literal ({@code -5} is one literal of value -5; JLS 3.10.1 needs
     * that for {@code -2147483648}). The literal's tree then starts at the
     * {@code -}. The TS reference parses the same text as negation applied to
     * the literal, which emits different bytes, so the minus is restored here.
     */
    private static boolean negatedLiteral(LiteralTree lt, Unit cu) {
        long start = cu.positions().getStartPosition(cu.cu(), lt);
        if (start < 0) return false;
        try {
            CharSequence text = cu.cu().getSourceFile().getCharContent(true);
            return start < text.length() && text.charAt((int) start) == '-';
        } catch (IOException e) {
            throw new ParseException("cannot read source text: " + e.getMessage());
        }
    }

    private static Expression convertLiteral(LiteralTree lt, String filename, Unit cu) {
        Object value = lt.getValue();
        if (value == null) {
            throw new ParseException("null literals are unsupported in " + filename);
        }
        if (value instanceof Integer || value instanceof Long) {
            BigInteger v = BigInteger.valueOf(((Number) value).longValue());
            if (negatedLiteral(lt, cu)) {
                return new UnaryExpr(Expression.UnaryOp.NEG, new BigIntLiteral(v.negate()));
            }
            return new BigIntLiteral(v);
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
            // F-011: the TS reference's text.
            throw new ParseException(filename + ": " + LexDiag.JAVA_CHAR_LITERAL);
        }
        if (value instanceof Double || value instanceof Float) {
            throw new ParseException("floating-point literals are unsupported in " + filename);
        }
        throw new ParseException("unsupported literal type " + value.getClass().getSimpleName() + " in " + filename);
    }

    private static Expression convertCall(MethodInvocationTree mi, String filename, Unit cu) {
        ExpressionTree callee = mi.getMethodSelect();
        // Recognise xxx.fromHex("deadbeef") → ByteStringLiteral.
        if (callee instanceof MemberSelectTree ms
            && ms.getIdentifier().contentEquals("fromHex")
            && mi.getArguments().size() == 1
            && mi.getArguments().get(0) instanceof LiteralTree hex
            && hex.getValue() instanceof String hs) {
            return new ByteStringLiteral(hs);
        }
        // Recognise asm("<hex>", in_arity, out_arity) — the asm() intrinsic
        // body is the only call position where a bare String literal is legal.
        // Lower the body to a ByteStringLiteral so the bare-String rejection
        // in convertLiteral never fires for it.
        if (callee instanceof IdentifierTree id && id.getName().contentEquals("asm")
            && !mi.getArguments().isEmpty()
            && mi.getArguments().get(0) instanceof LiteralTree body
            && body.getValue() instanceof String bodyStr) {
            List<Expression> asmArgs = new ArrayList<>(mi.getArguments().size());
            asmArgs.add(new ByteStringLiteral(bodyStr));
            for (int i = 1; i < mi.getArguments().size(); i++) {
                asmArgs.add(convertExpression(mi.getArguments().get(i), filename, cu));
            }
            return new CallExpr(new Identifier("asm"), asmArgs);
        }
        // Recognise BigInteger.valueOf(<int literal>) → BigIntLiteral, and
        // Bigint.of(<int literal>) as the equivalent shorthand on the Bigint
        // wrapper. Also accept the fully-qualified java.math.BigInteger.valueOf.
        if (callee instanceof MemberSelectTree ms
            && (isBigIntegerValueOf(ms) || isBigintOf(ms))
            && mi.getArguments().size() == 1
            && mi.getArguments().get(0) instanceof LiteralTree n
            && (n.getValue() instanceof Integer || n.getValue() instanceof Long)) {
            // F-026: only an int / long literal. A floating-point one
            // (`Bigint.of(1e3)`, `BigInteger.valueOf(1.5)`) used to be
            // truncated here by longValue(); it now falls through to
            // convertLiteral, which refuses it.
            return convertLiteral(n, filename, cu);
        }
        // Bigint.of(<arbitrary expression>) — wrapping a BigInteger-typed value
        // (e.g. the result of a builtin like `percentOf` or `extractLocktime`)
        // into a Bigint. At the Rúnar AST level Bigint and BigInteger collapse
        // to the same BIGINT primitive, so the wrap is a no-op: lower to the
        // inner expression. Mirrors how BigInteger.valueOf(<non-literal>) would
        // also collapse (the JDK valueOf is identity at this layer). Both the
        // bare BigInteger.valueOf and the qualified java.math.BigInteger.valueOf
        // forms are accepted.
        if (callee instanceof MemberSelectTree ms
            && (isBigIntegerValueOf(ms) || isBigintOf(ms))
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
        // <expr>.toByteString() — Java-side coercion of Point / Bigint / Sig /
        // PubKey wrappers to their raw byte form. Rúnar Point is structurally a
        // ByteString so the TS canonical sources pass Points directly to
        // builtins like `cat`. Lower to a no-op (drop the call, keep the
        // receiver) so the Java IR matches the canonical IR byte-for-byte.
        if (callee instanceof MemberSelectTree ms
            && ms.getIdentifier().contentEquals("toByteString")
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
        // Recognise <expr>.equals(<expr>) — Java's value-equality method on
        // ByteString/Addr/Sig/PubKey/etc. Java has no operator overloading, so
        // contracts spell byte-string equality as a.equals(b). Lower to the
        // canonical BinaryExpr(EQ, a, b). Matched by method name and arity;
        // receiver type is not consulted (the typechecker rejects misuse).
        if (callee instanceof MemberSelectTree ms
            && ms.getIdentifier().contentEquals("equals")
            && mi.getArguments().size() == 1) {
            Expression receiver = convertExpression(ms.getExpression(), filename, cu);
            Expression arg = convertExpression(mi.getArguments().get(0), filename, cu);
            return new BinaryExpr(Expression.BinaryOp.EQ, receiver, arg);
        }
        // General call: callee = expression, args = list.
        Expression calleeExpr = convertExpression(callee, filename, cu);
        List<Expression> args = convertArgs(mi, filename, cu);
        return new CallExpr(calleeExpr, args);
    }

    /**
     * True if {@code ms} names {@code BigInteger.valueOf} or the
     * fully-qualified {@code java.math.BigInteger.valueOf}.
     */
    private static boolean isBigIntegerValueOf(MemberSelectTree ms) {
        if (!ms.getIdentifier().contentEquals("valueOf")) return false;
        ExpressionTree receiver = ms.getExpression();
        if (receiver instanceof IdentifierTree bi && bi.getName().contentEquals("BigInteger")) {
            return true;
        }
        // java.math.BigInteger.valueOf — receiver is a MemberSelectTree whose
        // identifier is "BigInteger" and whose own receiver is "java.math".
        if (receiver instanceof MemberSelectTree outer
            && outer.getIdentifier().contentEquals("BigInteger")
            && outer.getExpression() instanceof MemberSelectTree mid
            && mid.getIdentifier().contentEquals("math")
            && mid.getExpression() instanceof IdentifierTree base
            && base.getName().contentEquals("java")) {
            return true;
        }
        return false;
    }

    /** True if {@code ms} names {@code Bigint.of}. */
    private static boolean isBigintOf(MemberSelectTree ms) {
        return ms.getIdentifier().contentEquals("of")
            && ms.getExpression() instanceof IdentifierTree id
            && id.getName().contentEquals("Bigint");
    }

    /** True if {@code op} is one of the six ordered comparison ops. */
    private static boolean isComparisonOp(Expression.BinaryOp op) {
        return op == Expression.BinaryOp.LT
            || op == Expression.BinaryOp.LE
            || op == Expression.BinaryOp.GT
            || op == Expression.BinaryOp.GE
            || op == Expression.BinaryOp.EQ
            || op == Expression.BinaryOp.NEQ;
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
        Unit cu
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

        if (("neg".equals(method) || "negate".equals(method)) && mi.getArguments().isEmpty()) {
            Expression receiver = convertExpression(ms.getExpression(), filename, cu);
            return Optional.of(new UnaryExpr(Expression.UnaryOp.NEG, receiver));
        }
        // a.not() -> UnaryExpr(~). Mirrors java.math.BigInteger#not(); the
        // Bigint wrapper exposes the same method so Rúnar Java sources can use
        // it natively.
        if ("not".equals(method) && mi.getArguments().isEmpty()) {
            Expression receiver = convertExpression(ms.getExpression(), filename, cu);
            return Optional.of(new UnaryExpr(Expression.UnaryOp.BIT_NOT, receiver));
        }
        if ("abs".equals(method) && mi.getArguments().isEmpty()) {
            // abs is a Rúnar builtin, not an operator: lower to CallExpr(abs, a).
            Expression receiver = convertExpression(ms.getExpression(), filename, cu);
            return Optional.of(new CallExpr(new Identifier("abs"), List.of(receiver)));
        }

        return Optional.empty();
    }

    /**
     * Bigint method-name → canonical BinaryOp table (unary ops handled
     * separately). Both the Bigint-wrapper spellings ({@code plus},
     * {@code minus}, ...) and the JDK {@link BigInteger} spellings
     * ({@code add}, {@code subtract}, {@code shiftLeft}, ...) map to the
     * same canonical BinaryOp. Receiver type is not consulted; the
     * typechecker rejects misuse.
     */
    private static final Map<String, Expression.BinaryOp> BIGINT_BINARY_METHODS = Map.ofEntries(
        // Bigint wrapper spellings.
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
        Map.entry("neq",   Expression.BinaryOp.NEQ),
        // JDK BigInteger spellings.
        Map.entry("add",        Expression.BinaryOp.ADD),
        Map.entry("subtract",   Expression.BinaryOp.SUB),
        Map.entry("multiply",   Expression.BinaryOp.MUL),
        Map.entry("divide",     Expression.BinaryOp.DIV),
        Map.entry("shiftLeft",  Expression.BinaryOp.SHL),
        Map.entry("shiftRight", Expression.BinaryOp.SHR)
    );

    private static List<Expression> convertArgs(MethodInvocationTree mi, String filename, Unit cu) {
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

    /** The compound-assignment set the TS reference accepts: + - * / % & | ^ << >>. */
    private static Expression.BinaryOp mapCompoundOp(Tree.Kind kind, String filename) {
        return switch (kind) {
            case PLUS_ASSIGNMENT -> Expression.BinaryOp.ADD;
            case MINUS_ASSIGNMENT -> Expression.BinaryOp.SUB;
            case MULTIPLY_ASSIGNMENT -> Expression.BinaryOp.MUL;
            case DIVIDE_ASSIGNMENT -> Expression.BinaryOp.DIV;
            case REMAINDER_ASSIGNMENT -> Expression.BinaryOp.MOD;
            case AND_ASSIGNMENT -> Expression.BinaryOp.BIT_AND;
            case OR_ASSIGNMENT -> Expression.BinaryOp.BIT_OR;
            case XOR_ASSIGNMENT -> Expression.BinaryOp.BIT_XOR;
            case LEFT_SHIFT_ASSIGNMENT -> Expression.BinaryOp.SHL;
            case RIGHT_SHIFT_ASSIGNMENT -> Expression.BinaryOp.SHR;
            default -> throw new ParseException("unsupported compound assignment operator " + kind + " in " + filename);
        };
    }

    private static Expression convertUnary(UnaryTree ut, String filename, Unit cu) {
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

    /**
     * N-093: the flag text of each {@code @Sighash} annotation in {@code mods},
     * or {@code null} for one whose argument is not exactly one string literal
     * ({@code @Sighash}, {@code @Sighash(1)}, {@code @Sighash(value = "...")},
     * ...), which is refused as a malformed spelling.
     */
    private static List<String> sighashSpecs(ModifiersTree mods) {
        List<String> specs = new ArrayList<>();
        if (mods == null) return specs;
        for (AnnotationTree a : mods.getAnnotations()) {
            if (!typeSimpleName(a.getAnnotationType()).equals("Sighash")) continue;
            List<? extends ExpressionTree> args = a.getArguments();
            if (args.size() == 1
                && args.get(0) instanceof LiteralTree lit
                && lit.getKind() == Tree.Kind.STRING_LITERAL) {
                specs.add((String) lit.getValue());
            } else {
                specs.add(null);
            }
        }
        return specs;
    }

    // F-205: the annotation names Rúnar recognizes at member position,
    // matching the TS reference (01-parse-java.ts, parseMember). Anything
    // else is a loud "unsupported annotation" diagnostic rather than a
    // silent visibility downgrade — e.g. a misspelled `@Publlic` used to
    // parse with no error and leave the method at the default `private`
    // visibility.
    private static final java.util.Set<String> KNOWN_MEMBER_ANNOTATIONS =
        java.util.Set.of("Readonly", "Public", "Stateful", "Override", "SuppressWarnings",
            // N-093: the native spellings of `@embedAlways` / `@sighash`.
            "EmbedAlways", "Sighash");

    private static void validateAnnotations(ModifiersTree mods) {
        if (mods == null) return;
        for (AnnotationTree a : mods.getAnnotations()) {
            String name = typeSimpleName(a.getAnnotationType());
            if (!KNOWN_MEMBER_ANNOTATIONS.contains(name)) {
                throw new ParseException("unsupported annotation @" + name);
            }
        }
    }

    private static String typeSimpleName(Tree t) {
        if (t instanceof IdentifierTree id) return id.getName().toString();
        if (t instanceof MemberSelectTree ms) return ms.getIdentifier().toString();
        if (t instanceof ParameterizedTypeTree pt) return typeSimpleName(pt.getType());
        return t.toString();
    }

    /**
     * Resolve a javac {@link Tree} to a Rúnar {@link SourceLocation}.
     *
     * <p>Rúnar's cross-tier source-map convention is <strong>1-based line,
     * 0-based column</strong>, where the column is a raw character index
     * into the line's text (see {@code conformance/source-map/README.md}
     * and {@code independent-oracle.ts}, which resolves a mapping by
     * indexing {@code lineText[column]}).
     *
     * <p>The column is therefore derived as {@code start - lineStart} rather
     * than from {@link LineMap#getColumnNumber}: the latter expands a tab to
     * the next 8-column stop, which would report column 16 for a two-tab
     * indent whose token actually sits at character index 2.
     *
     * <p>Positions javac cannot resolve ({@link Diagnostic#NOPOS}, e.g.
     * synthesised trees) stay at the degenerate {@code 0/0} — the source-anchor
     * oracle treats {@code line == 0} as "untracked" rather than as a wrong
     * position, so a genuine unknown must not be reported as line 1.
     */
    /**
     * {@code file:line:column: } for a javac diagnostic, with the same 0-based
     * raw character column as {@link #locationOf} (N-078, R88a): javac's own
     * {@code getColumnNumber} is 1-based and expands tabs to 8-column stops.
     */
    private static String javacDiagnosticLocation(String source, String filename, Diagnostic<?> d) {
        long pos = d.getPosition();
        if (pos == Diagnostic.NOPOS || pos < 0 || pos > source.length()) {
            return "";
        }
        int lineStart = source.lastIndexOf('\n', (int) pos - 1) + 1;
        return filename + ":" + d.getLineNumber() + ":" + (pos - lineStart) + ": ";
    }

    private static SourceLocation locationOf(Tree t, Unit cu, String filename) {
        if (t == null || cu == null) return new SourceLocation(filename, 0, 0);
        long start = cu.positions().getStartPosition(cu.cu(), t);
        if (start == Diagnostic.NOPOS || start < 0) return new SourceLocation(filename, 0, 0);
        LineMap lineMap = cu.cu().getLineMap();
        if (lineMap == null) return new SourceLocation(filename, 0, 0);
        long line = lineMap.getLineNumber(start);
        if (line < 1) return new SourceLocation(filename, 0, 0);
        long lineStart = lineMap.getStartPosition(line);
        return new SourceLocation(filename, (int) line, (int) Math.max(0, start - lineStart));
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
    // ---------------------------------------------------------------
    // F-213 measure (A) over the javac tree
    // ---------------------------------------------------------------

    /** Collects a tree's immediate children without recursing into them. */
    private static final class Children extends com.sun.source.util.TreeScanner<Void, List<Tree>> {
        private static final Children INSTANCE = new Children();

        @Override
        public Void scan(Tree tree, List<Tree> out) {
            if (tree != null) out.add(tree);
            return null;
        }

        static List<Tree> of(Tree t) {
            List<Tree> out = new ArrayList<>();
            t.accept(INSTANCE, out);
            return out;
        }
    }

    /** A statement context: a block, or a statement other than a class declaration. */
    private static boolean isStatementContext(Tree t) {
        return t instanceof BlockTree || (t instanceof StatementTree && !(t instanceof ClassTree));
    }

    /**
     * The parse-nesting counter (measure A) of {@code child}, given its
     * parent's. Mirrors what the TS reference's hand-written .runar.java parser
     * counts (01-parse-java.ts; same mapping as tsChildNesting in 01-parse.ts):
     * a statement inside a body (+1; a block is free unless it is itself a
     * nested statement), each expression slot of a statement / declaration, a
     * parenthesised group, a call or {@code new} argument, an array-access
     * index, an array-initializer element, a ternary arm, a prefix-unary
     * operand, a type argument. Binary operands, assignment sides, member
     * objects and callees add nothing. A for's init / update are parsed as
     * part of the for (their expressions are its slots), and javac's
     * parenthesised if / while / switch condition IS the slot, not a group
     * inside it.
     */
    private static int childNesting(Tree parent, Tree child, int level) {
        if (parent instanceof ForLoopTree fl) {
            if (fl.getInitializer().contains(child) || fl.getUpdate().contains(child)) return level;
            if (child == fl.getCondition()) return level + 1;
        }
        if (child instanceof StatementTree && isStatementContext(parent)) {
            if (child instanceof BlockTree && !(parent instanceof BlockTree)) return level;
            return level + 1;
        }
        if (parent instanceof ExpressionStatementTree es) {
            return child == es.getExpression() ? level + 1 : level;
        }
        if (parent instanceof ReturnTree rt) {
            return child == rt.getExpression() ? level + 1 : level;
        }
        if (parent instanceof com.sun.source.tree.ThrowTree tt) {
            return child == tt.getExpression() ? level + 1 : level;
        }
        if (parent instanceof IfTree it) {
            return child == it.getCondition() ? conditionSlot(child, level) : level;
        }
        if (parent instanceof com.sun.source.tree.WhileLoopTree wt) {
            return child == wt.getCondition() ? conditionSlot(child, level) : level;
        }
        if (parent instanceof com.sun.source.tree.DoWhileLoopTree dt) {
            return child == dt.getCondition() ? conditionSlot(child, level) : level;
        }
        if (parent instanceof com.sun.source.tree.SwitchTree st) {
            return child == st.getExpression() ? conditionSlot(child, level) : level;
        }
        if (parent instanceof VariableTree v) {
            return child == v.getInitializer() ? level + 1 : level;
        }
        if (parent instanceof ParenthesizedTree) {
            return level + 1;
        }
        if (parent instanceof UnaryTree ut) {
            return switch (ut.getKind()) {
                case POSTFIX_INCREMENT, POSTFIX_DECREMENT -> level;
                default -> level + 1;
            };
        }
        if (parent instanceof NewArrayTree na) {
            boolean slot = (na.getInitializers() != null && na.getInitializers().contains(child))
                || (na.getDimensions() != null && na.getDimensions().contains(child));
            return slot ? level + 1 : level;
        }
        if (parent instanceof MethodInvocationTree mi) {
            return mi.getArguments().contains(child) ? level + 1 : level;
        }
        if (parent instanceof NewClassTree nc) {
            return nc.getArguments().contains(child) ? level + 1 : level;
        }
        if (parent instanceof ArrayAccessTree aa) {
            return child == aa.getIndex() ? level + 1 : level;
        }
        if (parent instanceof ConditionalExpressionTree ce) {
            return child == ce.getCondition() ? level : level + 1;
        }
        if (parent instanceof ParameterizedTypeTree pt) {
            return pt.getTypeArguments().contains(child) ? level + 1 : level;
        }
        return level;
    }

    /** javac keeps the parens of {@code if (c)}: they are the slot, so the group adds nothing. */
    private static int conditionSlot(Tree cond, int level) {
        return cond instanceof ParenthesizedTree ? level : level + 1;
    }

    private record Nesting(Tree tree, int level) {}

    /** The first tree whose parse nesting exceeds the limit, or null. Iterative. */
    private static Tree parseNestingViolation(CompilationUnitTree cu) {
        java.util.ArrayDeque<Nesting> work = new java.util.ArrayDeque<>();
        work.push(new Nesting(cu, 0));
        while (!work.isEmpty()) {
            Nesting n = work.pop();
            if (n.level() > InputLimits.MAX_SOURCE_NESTING) return n.tree();
            for (Tree child : Children.of(n.tree())) {
                work.push(new Nesting(child, childNesting(n.tree(), child, n.level())));
            }
        }
        return null;
    }

    public static final class ParseException extends RuntimeException {
        public ParseException(String message) {
            super(message);
        }
    }
}
