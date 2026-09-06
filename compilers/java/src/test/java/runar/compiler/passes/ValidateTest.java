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
    void rejectsReturnInPublicMethod() {
        // Public methods compile as spending entry points. `return` is a
        // PRIVATE-helper construct: spec/grammar.md:161 makes them void,
        // :162 makes the trailing assert their spending condition, and
        // spec/semantics.md §4.7 sequences statements unconditionally, so
        // there is no early exit to lower.
        //
        // This test used to assert the OPPOSITE for the bare form — "uses
        // only `return;` (no value) so it should be OK" — and that hole is
        // NEW-012: the arm carrying the bare `return;` contributed no result,
        // yielded OP_0, and the whole script evaluated FALSE. Source compiled
        // clean, `Spend` rejected the spend, the UTXO was unspendable. Both
        // spellings are errors now.
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
        // Bare `return;` — rejected (NEW-012).
        ContractNode bareReturn = JavaParser.parse(src, "BareReturn.runar.java");
        Validate.ValidationException bareErr = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(bareReturn)
        );
        assertTrue(
            bareErr.errors().stream().anyMatch(m -> m.contains("must not use `return`")),
            "expected bare-return error, got " + bareErr.errors()
        );

        // `return expr;` — rejected too, as it always has been here.
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
            e.errors().stream().anyMatch(m -> m.contains("must not use `return`")),
            "expected return error, got " + e.errors()
        );
    }

    @Test
    void allowsReturnInPrivateHelper() {
        // spec/grammar.md:168 — "Private methods may return a value." The
        // rejection above must not spill onto the inlined-helper form, which
        // is how ~340 in-repo contracts legitimately use `return`.
        String src = """
            class Ok extends SmartContract {
                @Readonly Bigint x;

                Ok(Bigint x) {
                    super(x);
                    this.x = x;
                }

                Bigint doubled(Bigint v) {
                    return v.add(v);
                }

                @Public
                void check(Bigint y) {
                    assertThat(this.doubled(y) == this.x);
                }
            }
            """;
        ContractNode ok = JavaParser.parse(src, "Ok.runar.java");
        assertDoesNotThrow(() -> Validate.run(ok));
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

    @Test
    void rejectsForLoopWithIdentifierBound() {
        // A bare identifier bound (a method parameter here) is not unrollable
        // into fixed Bitcoin Script; the reference TS compiler rejects it, so
        // the validator must too (anf-lower would otherwise throw).
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void unlock(Bigint n) {
                    for (Bigint i = BigInteger.ZERO; i < n; i++) {
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

    // ------------------------------------------------------------------
    // No public methods (issue #120)
    // ------------------------------------------------------------------

    @Test
    void rejectsContractWithNoPublicMethods() {
        // Every method defaults to private without @Public — the contract has
        // no spending entry point and would compile to an empty script.
        String src = """
            class Locked extends SmartContract {
                @Readonly PubKey pk;

                Locked(PubKey pk) {
                    super(pk);
                    this.pk = pk;
                }

                void unlock(Sig sig) {
                    assertThat(checkSig(sig, this.pk));
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Locked.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("no public methods")),
            "expected no-public-methods error, got " + e.errors()
        );
    }

    @Test
    void rejectsContractWithNoMethodsAtAll() {
        String src = """
            class Empty extends SmartContract {
                @Readonly Bigint x;

                Empty(Bigint x) {
                    super(x);
                    this.x = x;
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Empty.runar.java");
        Validate.ValidationException e = assertThrows(
            Validate.ValidationException.class,
            () -> Validate.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("no public methods")),
            "expected no-public-methods error, got " + e.errors()
        );
    }

    @Test
    void acceptsContractWithAtLeastOnePublicMethod() {
        ContractNode c = JavaParser.parse(VALID_P2PKH, "P2PKH.runar.java");
        Validate.Result r = Validate.runCollecting(c);
        assertFalse(
            r.errors().stream().anyMatch(m -> m.contains("no public methods")),
            "did not expect no-public-methods error, got " + r.errors()
        );
    }

    // ------------------------------------------------------------------
    // Non-zero-start and countdown loop shapes (issue #121)
    // ------------------------------------------------------------------

    @Test
    void acceptsForLoopWithNonZeroStart() {
        String src = """
            class C extends SmartContract {
                @Readonly Bigint x;

                C(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void m() {
                    for (Bigint i = 1; i <= 3; i++) {
                        assertThat(true);
                    }
                    assertThat(true);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "C.runar.java");
        // Issue #121: a non-zero-start loop is now supported and must validate.
        assertDoesNotThrow(() -> Validate.run(c));
    }

    @Test
    void acceptsCountdownForLoop() {
        String src = """
            class C extends SmartContract {
                @Readonly Bigint x;

                C(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void m() {
                    for (Bigint i = 3; i > 0; i--) {
                        assertThat(true);
                    }
                    assertThat(true);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "C.runar.java");
        // Issue #121: a countdown loop is now supported and must validate.
        assertDoesNotThrow(() -> Validate.run(c));
    }

    @Test
    void acceptsZeroStartCountingUpForLoop() {
        String src = """
            class C extends SmartContract {
                @Readonly Bigint x;

                C(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void m() {
                    for (Bigint i = 0; i <= 3; i++) {
                        assertThat(true);
                    }
                    assertThat(true);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "C.runar.java");
        Validate.Result r = Validate.runCollecting(c);
        assertFalse(
            r.errors().stream().anyMatch(m ->
                m.contains("must start at 0") || m.contains("countdown")),
            "did not expect loop-shape error, got " + r.errors()
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
