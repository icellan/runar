package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.builtins.BuiltinRegistry;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.ast.ContractNode;

class TypecheckTest {

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
    // Happy paths
    // ------------------------------------------------------------------

    @Test
    void acceptsValidP2pkh() {
        ContractNode c = JavaParser.parse(VALID_P2PKH, "P2PKH.runar.java");
        List<String> errs = Typecheck.collect(c);
        assertTrue(errs.isEmpty(), "expected no errors, got " + errs);
    }

    @Test
    void acceptsValidStatefulCounter() {
        ContractNode c = JavaParser.parse(VALID_COUNTER, "Counter.runar.java");
        List<String> errs = Typecheck.collect(c);
        assertTrue(errs.isEmpty(), "expected no errors, got " + errs);
    }

    // ------------------------------------------------------------------
    // Builtin registry coverage
    // ------------------------------------------------------------------

    @Test
    void builtinRegistryExposesCoreFunctions() {
        assertTrue(BuiltinRegistry.isBuiltin("sha256"));
        assertTrue(BuiltinRegistry.isBuiltin("hash160"));
        assertTrue(BuiltinRegistry.isBuiltin("checkSig"));
        assertTrue(BuiltinRegistry.isBuiltin("checkMultiSig"));
        assertTrue(BuiltinRegistry.isBuiltin("verifyWOTS"));
        assertTrue(BuiltinRegistry.isBuiltin("verifySLHDSA_SHA2_128s"));
        assertTrue(BuiltinRegistry.isBuiltin("verifySLHDSA_SHA2_256f"));
        assertTrue(BuiltinRegistry.isBuiltin("ecAdd"));
        assertTrue(BuiltinRegistry.isBuiltin("p256Add"));
        assertTrue(BuiltinRegistry.isBuiltin("p384MulGen"));
        assertTrue(BuiltinRegistry.isBuiltin("bbFieldAdd"));
        assertTrue(BuiltinRegistry.isBuiltin("kbExt4Mul3"));
        assertTrue(BuiltinRegistry.isBuiltin("bn254G1OnCurve"));
        assertTrue(BuiltinRegistry.isBuiltin("merkleRootSha256"));
        assertFalse(BuiltinRegistry.isBuiltin("console.log"));
        assertFalse(BuiltinRegistry.isBuiltin("Math.floor"));
    }

    @Test
    void builtinSignatureShapeMatchesPythonReference() {
        var hash160 = BuiltinRegistry.lookup("hash160").orElseThrow();
        assertEquals(1, hash160.arity());
        assertEquals("ByteString", hash160.params().get(0).type());
        assertEquals("Ripemd160", hash160.returnType());

        var checkSig = BuiltinRegistry.lookup("checkSig").orElseThrow();
        assertEquals(2, checkSig.arity());
        assertEquals("Sig", checkSig.params().get(0).type());
        assertEquals("PubKey", checkSig.params().get(1).type());
        assertEquals("boolean", checkSig.returnType());
    }

    // ------------------------------------------------------------------
    // Error paths
    // ------------------------------------------------------------------

    @Test
    void rejectsUnknownFreeFunctionCall() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void unlock() {
                    assertThat(frobulate(this.x) == BigInteger.ONE);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Typecheck.TypeCheckException e = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("frobulate")),
            "expected unknown-fn error, got " + e.errors()
        );
    }

    @Test
    void rejectsWrongArgCountOnBuiltin() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Addr a;

                Bad(Addr a) {
                    super(a);
                    this.a = a;
                }

                @Public
                void unlock(Sig sig, PubKey pubKey) {
                    assertThat(checkSig(sig));
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Typecheck.TypeCheckException e = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("checkSig")
                && m.contains("argument")),
            "expected wrong-arg-count error, got " + e.errors()
        );
    }

    @Test
    void rejectsWrongTypeOnBinaryOp() {
        // Adding bigint to a PubKey (ByteString family) is not allowed.
        // `+` with a PubKey on the left would only be valid if both sides
        // were ByteString-family; bigint + PubKey is rejected.
        String src = """
            class Bad extends SmartContract {
                @Readonly PubKey pk;

                Bad(PubKey pk) {
                    super(pk);
                    this.pk = pk;
                }

                @Public
                void unlock() {
                    Bigint x = BigInteger.ONE + this.pk;
                    assertThat(x == BigInteger.TEN);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Typecheck.TypeCheckException e = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("must be bigint")),
            "expected binary-op type error, got " + e.errors()
        );
    }

    @Test
    void rejectsTernaryWithMismatchedBranches() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint threshold;
                @Readonly PubKey pk;

                Bad(Bigint threshold, PubKey pk) {
                    super(threshold, pk);
                    this.threshold = threshold;
                    this.pk = pk;
                }

                @Public
                void unlock(Bigint y) {
                    Bigint x = y > this.threshold ? BigInteger.ONE : this.pk;
                    assertThat(x == BigInteger.TEN);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Typecheck.TypeCheckException e = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("ternary branches")
                || m.contains("is not assignable")),
            "expected mismatched-ternary error, got " + e.errors()
        );
    }

    @Test
    void rejectsReturnValueFromPublicMethod() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void unlock(Bigint y) {
                    if (y == BigInteger.ZERO) {
                        return 42;
                    }
                    assertThat(true);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Typecheck.TypeCheckException e = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("must not return a value")),
            "expected return-value error, got " + e.errors()
        );
    }

    @Test
    void rejectsAssertOnNonBooleanCondition() {
        String src = """
            class Bad extends SmartContract {
                @Readonly Bigint x;

                Bad(Bigint x) {
                    super(x);
                    this.x = x;
                }

                @Public
                void unlock() {
                    assertThat(this.x);
                }
            }
            """;
        ContractNode c = JavaParser.parse(src, "Bad.runar.java");
        Typecheck.TypeCheckException e = assertThrows(
            Typecheck.TypeCheckException.class,
            () -> Typecheck.run(c)
        );
        assertTrue(
            e.errors().stream().anyMatch(m -> m.contains("must be boolean")),
            "expected assert-boolean error, got " + e.errors()
        );
    }

    @Test
    void acceptsHash160EqualsComparison() {
        // Regression: the equals(...) call on a ByteString-family type
        // should return boolean and not produce a type error inside
        // assertThat(...).
        String src = """
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
        ContractNode c = JavaParser.parse(src, "P2PKH.runar.java");
        List<String> errs = Typecheck.collect(c);
        assertTrue(errs.isEmpty(), "expected no errors, got " + errs);
    }
}
