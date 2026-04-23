package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.ast.ContractNode;

class ValidateTest {

    private static final String VALID_P2PKH = """
        class P2PKH extends SmartContract {
            @Readonly Addr pubKeyHash;

            P2PKH(Addr pubKeyHash) {
                super(pubKeyHash);
                this.pubKeyHash = pubKeyHash;
            }

            @Public
            void unlock(Sig sig, PubKey pubKey) {
                assertThat(hash160(pubKey).equals(pubKeyHash));
                assertThat(checkSig(sig, pubKey));
            }
        }
        """;

    private static final String VALID_COUNTER = """
        class Counter extends StatefulSmartContract {
            Bigint count;

            Counter(Bigint count) {
                super(count);
                this.count = count;
            }

            @Public
            void increment() {
                this.count = this.count + BigInteger.ONE;
            }
        }
        """;

    // ------------------------------------------------------------------
    // Happy path
    // ------------------------------------------------------------------

    @Test
    void acceptsValidP2pkh() {
        ContractNode c = JavaParser.parse(VALID_P2PKH, "P2PKH.runar.java");
        List<String> warnings = Validate.run(c);
        assertTrue(warnings.isEmpty(), "expected no warnings, got " + warnings);
    }

    @Test
    void acceptsValidStatefulCounter() {
        ContractNode c = JavaParser.parse(VALID_COUNTER, "Counter.runar.java");
        List<String> warnings = Validate.run(c);
        assertTrue(warnings.isEmpty(), "expected no warnings, got " + warnings);
    }

    @Test
    void acceptsPropertyInitializerLiteral() {
        String src = """
            class Counter extends StatefulSmartContract {
                Bigint count = BigInteger.ZERO;
                @Readonly PubKey owner;

                Counter(PubKey owner) {
                    super(owner);
                    this.owner = owner;
                }

                @Public
                void bump() {
                    this.count = this.count + BigInteger.ONE;
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Counter.runar.java");
        assertDoesNotThrow(() -> Validate.run(c));
    }

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    @Test
    void rejectsConstructorWithoutSuper() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Addr a;

                Bad(Addr a) {
                    this.a = a;
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("super()")),
            "expected super() error, got " + e.errors()
        );
    }

    @Test
    void rejectsMultipleConstructorsAtParseTime() {
        // The parser already rejects multiple constructors with a clear error,
        // but validate-after-parse is a no-op in that case. This defensive
        // test asserts the parser message is surfaced before we run validate.
        String src = """
            class Bad extends SmartContract {
                @Readonly Addr a;
                Bad() { super(); }
                Bad(Addr a) { super(a); this.a = a; }
            }
            """;
        JavaParser.ParseException e = assertThrows(
            JavaParser.ParseException.class,
            () -> JavaParser.parse(src, "Bad.runar.java")
        );
        assertTrue(e.getMessage().contains("more than one constructor"));
    }

    // ------------------------------------------------------------------
    // Property initializers
    // ------------------------------------------------------------------

    @Test
    void rejectsNonLiteralPropertyInitializer() {
        String src = """
            class Bad extends StatefulSmartContract {
                Bigint count = hash160(BigInteger.ZERO);
                @Readonly PubKey owner;

                Bad(PubKey owner) {
                    super(owner);
                    this.owner = owner;
                }

                @Public
                void noop() {
                    assertThat(true);
                }
            }
            """;
        // The ByteString literal here wouldn't type-check either, but
        // the validator catches the non-literal initializer directly.
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("must be a literal value")),
            "expected literal-initializer error, got " + e.errors()
        );
    }

    // ------------------------------------------------------------------
    // Property mutability
    // ------------------------------------------------------------------

    @Test
    void rejectsMutablePropertyInSmartContract() {
        String src = """
            class Bad extends SmartContract {
                Bigint counter;

                Bad(Bigint counter) {
                    super(counter);
                    this.counter = counter;
                }

                @Public
                void unlock() {
                    assertThat(true);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("must be readonly")),
            "expected readonly error, got " + e.errors()
        );
    }

    // ------------------------------------------------------------------
    // Returning values from public methods
    // ------------------------------------------------------------------

    @Test
    void rejectsReturnValueFromPublicMethod() {
        // Public methods compile as spending entry points; returning a value
        // has no meaning and is not allowed by the Rúnar subset.
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void check(Bigint y) {
                    if (y == BigInteger.ZERO) {
                        return;
                    }
                    assertThat(y == this.x);
                }
            }
            """;
        // The method above uses only `return;` (no value) so it should be OK.
        ContractNode ok = JavaParser.parse(src, "OkReturn.runar.java");
        assertDoesNotThrow(() -> Validate.run(ok));

        // Now a `return expr;` in a public method must be rejected.
        String badSrc = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void check(Bigint y) {
                    if (y == BigInteger.ZERO) {
                        return 42;
                    }
                    assertThat(y == this.x);
                }
            }
            """;
        ContractNode bad = JavaParser.parse(badSrc, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(bad)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("must not return a value")),
            "expected return-value error, got " + e.errors()
        );
    }

    // ------------------------------------------------------------------
    // Recursion
    // ------------------------------------------------------------------

    @Test
    void rejectsDirectRecursion() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void unlock() {
                    this.loop(this.x);
                    assertThat(true);
                }

                void loop(Bigint n) {
                    this.loop(n);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("recursion detected")),
            "expected recursion error, got " + e.errors()
        );
    }

    // ------------------------------------------------------------------
    // For-loop bounds
    // ------------------------------------------------------------------

    @Test
    void rejectsForLoopWithNonConstantBound() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint bound;

                Bad(Bigint bound) {
                    super(bound);
                    this.bound = bound;
                }

                @Public
                void unlock() {
                    for (Bigint i = BigInteger.ZERO; i < this.bound; i++) {
                        assertThat(true);
                    }
                    assertThat(true);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("compile-time constant")),
            "expected for-loop-bound error, got " + e.errors()
        );
    }

    // ------------------------------------------------------------------
    // Unknown function calls
    // ------------------------------------------------------------------

    @Test
    void rejectsUnknownFunctionCallOutsideBuiltinRegistry() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void unlock() {
                    frobulate(this.x);
                    assertThat(true);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("frobulate")),
            "expected unknown-function error, got " + e.errors()
        );
    }

    @Test
    void rejectsPublicMethodWithoutFinalAssert() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void unlock() {
                    Bigint y = this.x + BigInteger.ONE;
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("must end with an assert")),
            "expected trailing-assert error, got " + e.errors()
        );
    }
}
