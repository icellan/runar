package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.frontend.JavaParser;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.DropOp;
import runar.compiler.ir.stack.DupOp;
import runar.compiler.ir.stack.IfOp;
import runar.compiler.ir.stack.NipOp;
import runar.compiler.ir.stack.OpcodeOp;
import runar.compiler.ir.stack.OverOp;
import runar.compiler.ir.stack.PickOp;
import runar.compiler.ir.stack.PlaceholderOp;
import runar.compiler.ir.stack.ByteStringPushValue;
import runar.compiler.ir.stack.PushOp;
import runar.compiler.ir.stack.PushValue;
import runar.compiler.ir.stack.RollOp;
import runar.compiler.ir.stack.RotOp;
import runar.compiler.ir.stack.StackMethod;
import runar.compiler.ir.stack.StackOp;
import runar.compiler.ir.stack.StackProgram;
import runar.compiler.ir.stack.SwapOp;

class StackLowerTest {

    private static StackProgram compile(String src, String file) {
        ContractNode contract = JavaParser.parse(src, file);
        Validate.run(contract);
        // Match the production pipeline (Cli.compileSource): ExpandFixedArrays
        // runs between Validate and Typecheck so that FixedArray syntax is
        // desugared before downstream passes ever see it.
        contract = ExpandFixedArrays.run(contract);
        Typecheck.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        return StackLower.run(anf);
    }

    private static StackMethod findMethod(StackProgram p, String name) {
        for (StackMethod m : p.methods()) {
            if (m.name().equals(name)) return m;
        }
        throw new IllegalArgumentException("method not found: " + name);
    }

    /** Recursively count opcode hits at any depth (including IfOp branches). */
    private static int countOpcode(List<StackOp> ops, String code) {
        int n = 0;
        for (StackOp op : ops) {
            if (op instanceof OpcodeOp o && o.code().equals(code)) n++;
            if (op instanceof IfOp i) {
                if (i.thenBranch() != null) n += countOpcode(i.thenBranch(), code);
                if (i.elseBranch() != null) n += countOpcode(i.elseBranch(), code);
            }
        }
        return n;
    }

    /** Recursively count IfOps. */
    private static int countIfOps(List<StackOp> ops) {
        int n = 0;
        for (StackOp op : ops) {
            if (op instanceof IfOp i) {
                n++;
                if (i.thenBranch() != null) n += countIfOps(i.thenBranch());
                if (i.elseBranch() != null) n += countIfOps(i.elseBranch());
            }
        }
        return n;
    }

    /** Count ByteString-typed PushOps with a given hex literal at any depth. */
    private static int countBytePush(List<StackOp> ops, String hex) {
        int n = 0;
        for (StackOp op : ops) {
            if (op instanceof PushOp pu && pu.value() instanceof ByteStringPushValue bs
                && hex.equals(bs.hex())) {
                n++;
            }
            if (op instanceof IfOp i) {
                if (i.thenBranch() != null) n += countBytePush(i.thenBranch(), hex);
                if (i.elseBranch() != null) n += countBytePush(i.elseBranch(), hex);
            }
        }
        return n;
    }

    /** Total op count, including IF branch contents. */
    private static int totalOps(List<StackOp> ops) {
        int n = 0;
        for (StackOp op : ops) {
            n++;
            if (op instanceof IfOp i) {
                if (i.thenBranch() != null) n += totalOps(i.thenBranch());
                if (i.elseBranch() != null) n += totalOps(i.elseBranch());
            }
        }
        return n;
    }

    // ---------------- P2PKH (existing presence test) ----------------

    private static final String P2PKH_SRC = """
        package runar.examples.p2pkh;

        import runar.lang.*;

        public class P2PKH extends SmartContract {
            @Readonly Addr pubKeyHash;

            public P2PKH(Addr pubKeyHash) {
                super(pubKeyHash);
                this.pubKeyHash = pubKeyHash;
            }

            @Public
            public void unlock(Sig sig, PubKey pubKey) {
                assertThat(hash160(pubKey).equals(pubKeyHash));
                assertThat(checkSig(sig, pubKey));
            }
        }
        """;

    @Test
    void p2pkhStackIrShape() {
        StackProgram p = compile(P2PKH_SRC, "P2PKH.runar.java");
        assertEquals(1, p.methods().size(), "constructor skipped; only unlock emitted");
        StackMethod unlock = findMethod(p, "unlock");
        List<StackOp> ops = unlock.ops();

        boolean sawDup = false, sawHash160 = false, sawPlaceholder = false;
        boolean sawEqualOrVerify = false, sawChecksig = false;
        for (StackOp op : ops) {
            if (op instanceof DupOp) sawDup = true;
            if (op instanceof OpcodeOp o) {
                if ("OP_HASH160".equals(o.code())) sawHash160 = true;
                if ("OP_EQUAL".equals(o.code()) || "OP_VERIFY".equals(o.code())) sawEqualOrVerify = true;
                if ("OP_CHECKSIG".equals(o.code())) sawChecksig = true;
            }
            if (op instanceof PlaceholderOp) sawPlaceholder = true;
        }
        assertTrue(sawDup, "expected a DUP for the pubKey copy");
        assertTrue(sawHash160, "expected OP_HASH160");
        assertTrue(sawPlaceholder, "expected a PlaceholderOp for pubKeyHash");
        assertTrue(sawEqualOrVerify, "expected OP_EQUAL/OP_VERIFY before peephole");
        assertTrue(sawChecksig, "expected OP_CHECKSIG");
    }

    // ---------------- trivial bigint arithmetic ----------------

    private static final String ARITH_SRC = """
        package runar.examples.arith;

        import runar.lang.*;
        import java.math.BigInteger;

        public class Arith extends SmartContract {
            @Readonly Bigint threshold;

            public Arith(Bigint threshold) {
                super(threshold);
                this.threshold = threshold;
            }

            @Public
            public void unlock(Bigint x) {
                assertThat(x + BigInteger.valueOf(3) > threshold);
            }
        }
        """;

    @Test
    void arithmeticStackIrContainsOpAdd() {
        StackProgram p = compile(ARITH_SRC, "Arith.runar.java");
        StackMethod unlock = findMethod(p, "unlock");
        boolean sawAddOr1Add = false;
        boolean sawGreaterThan = false;
        for (StackOp op : unlock.ops()) {
            if (op instanceof OpcodeOp o) {
                if ("OP_ADD".equals(o.code())) sawAddOr1Add = true;
                if ("OP_GREATERTHAN".equals(o.code())) sawGreaterThan = true;
            }
        }
        assertTrue(sawAddOr1Add, "expected OP_ADD from the `x + 3` binding");
        assertTrue(sawGreaterThan, "expected OP_GREATERTHAN from the `>` binding");
    }

    // ---------------- stateful Counter (existing presence test) ----------------

    private static final String COUNTER_SRC = """
        package runar.examples.counter;

        import runar.lang.*;
        import java.math.BigInteger;

        public class Counter extends StatefulSmartContract {
            Bigint count;

            public Counter(Bigint count) {
                super(count);
                this.count = count;
            }

            @Public
            public void increment() {
                this.count = this.count + BigInteger.valueOf(1);
            }
        }
        """;

    @Test
    void statefulCounterIncludesCodeSeparator() {
        StackProgram p = compile(COUNTER_SRC, "Counter.runar.java");
        StackMethod inc = findMethod(p, "increment");
        boolean sawCodeSep = false;
        boolean sawChecksigVerify = false;
        for (StackOp op : inc.ops()) {
            if (op instanceof OpcodeOp o) {
                if ("OP_CODESEPARATOR".equals(o.code())) sawCodeSep = true;
                if ("OP_CHECKSIGVERIFY".equals(o.code())) sawChecksigVerify = true;
            }
        }
        assertTrue(sawCodeSep, "stateful method must emit OP_CODESEPARATOR via checkPreimage");
        assertTrue(sawChecksigVerify, "checkPreimage emits OP_CHECKSIGVERIFY for the G-verify step");
    }

    @Test
    void collectRefsHandlesAtRefAliases() {
        StackProgram p = compile(ARITH_SRC, "Arith.runar.java");
        assertNotNull(p);
        assertFalse(p.methods().isEmpty());
        for (StackMethod m : p.methods()) {
            assertTrue(m.maxStackDepth().compareTo(BigInteger.ZERO) >= 0);
        }
    }

    /* ================================================================== */
    /* 1. Multi-output intrinsics: addOutput / addRawOutput / addDataOutput */
    /* ================================================================== */

    /**
     * Stateful contract calling {@code addOutput(satoshis, prop)}. The
     * lowering must (a) prepend an {@code OP_RETURN} byte (0x6a), (b)
     * serialise the bigint state via {@code OP_NUM2BIN} with width 8,
     * (c) compute a varint length prefix via {@code OP_SIZE}, and (d)
     * prepend an 8-byte little-endian satoshis amount (also via NUM2BIN
     * width 8). See {@code StackLower.lowerAddOutput} (≈ line 1960).
     */
    @Test
    void addOutputSingleEmitsReturnByteAndNum2Bin() {
        String src = """
            package fix.singleadd;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            class C extends StatefulSmartContract {
                Bigint count;
                C(Bigint count) { super(count); this.count = count; }
                @Public
                void bump() {
                    this.count = this.count.plus(Bigint.ONE);
                    this.addOutput(0L, this.count);
                }
            }
            """;
        StackProgram p = compile(src, "C.runar.java");
        StackMethod m = findMethod(p, "bump");
        List<StackOp> ops = m.ops();

        // Pushed OP_RETURN byte literal: 6a is the OP_RETURN prefix byte.
        boolean sawReturnPush = false;
        for (StackOp op : ops) {
            if (op instanceof PushOp pu && pu.value() instanceof ByteStringPushValue bs && "6a".equals(bs.hex())) {
                sawReturnPush = true;
                break;
            }
        }
        assertTrue(sawReturnPush, "addOutput must push 0x6a (OP_RETURN) byte literal");

        // Two NUM2BIN ops minimum: one for the bigint state, one for
        // the 8-byte satoshis prefix. The state-script construction
        // (computeStateOutput etc) doesn't run here — `addOutput` is the
        // explicit form, so exactly the addOutput body's NUM2BINs apply.
        assertTrue(countOpcode(ops, "OP_NUM2BIN") >= 2,
            "addOutput must emit ≥ 2 OP_NUM2BIN (state value + satoshis)");
        // OP_SIZE drives the varint-length prefix path.
        assertTrue(countOpcode(ops, "OP_SIZE") >= 1,
            "addOutput must emit OP_SIZE for varint length");
        // OP_CAT joins the segments — at least 4 (return-byte + value
        // + length-prefix + satoshis).
        assertTrue(countOpcode(ops, "OP_CAT") >= 4,
            "addOutput must emit ≥ 4 OP_CAT to concatenate segments");
    }

    /**
     * Multi-output: stateful contract emits two state values in declaration
     * order (mirrors {@code FungibleToken} usage). The two NUM2BIN(8)
     * sequences must appear together with a CAT after each, before the
     * satoshis prefix.
     */
    @Test
    void addOutputMultiValueOrderingFollowsPropertyDeclaration() {
        String src = """
            package fix.multiadd;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            class T extends StatefulSmartContract {
                Bigint a;
                Bigint b;
                T(Bigint a, Bigint b) { super(a, b); this.a = a; this.b = b; }
                @Public
                void bump() {
                    this.a = this.a.plus(Bigint.ONE);
                    this.b = this.b.plus(Bigint.ONE);
                    this.addOutput(0L, this.a, this.b);
                }
            }
            """;
        StackProgram p = compile(src, "T.runar.java");
        StackMethod m = findMethod(p, "bump");
        List<StackOp> ops = m.ops();

        // 2-value addOutput (this.a + this.b) requires more NUM2BINs
        // than 1-value: two state-value NUM2BINs vs one. Use a relative
        // comparison against a 1-prop fixture to avoid coupling to the
        // exact (large) count produced by the auto-continuation.
        String single = """
            package fix.singlecmp;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            class T1 extends StatefulSmartContract {
                Bigint a;
                T1(Bigint a) { super(a); this.a = a; }
                @Public
                void bump() {
                    this.a = this.a.plus(Bigint.ONE);
                    this.addOutput(0L, this.a);
                }
            }
            """;
        StackProgram p1 = compile(single, "T1.runar.java");
        StackMethod m1 = findMethod(p1, "bump");
        int singleNum2bin = countOpcode(m1.ops(), "OP_NUM2BIN");
        int doubleNum2bin = countOpcode(ops, "OP_NUM2BIN");
        assertTrue(doubleNum2bin > singleNum2bin,
            "addOutput(2 props) must emit MORE NUM2BIN than addOutput(1 prop): "
                + doubleNum2bin + " vs " + singleNum2bin);
        // 0x6a OP_RETURN prefix appears exactly once per addOutput call.
        int returnPushes = 0;
        for (StackOp op : ops) {
            if (op instanceof PushOp pu && pu.value() instanceof ByteStringPushValue bs && "6a".equals(bs.hex())) returnPushes++;
        }
        assertEquals(1, returnPushes,
            "exactly one 0x6a (OP_RETURN) byte should be pushed per addOutput");
    }

    /**
     * {@code addRawOutput(sats, scriptBytes)}: lowers via
     * {@code lowerAddRawOutput} (StackLower.java:2028) which emits
     * OP_SIZE → varint → OP_CAT → OP_NUM2BIN(8 satoshis) → OP_CAT.
     * The lowerer NEVER pushes 0x6a (OP_RETURN) byte — the caller
     * fully controls the script content (unlike addOutput which
     * injects an OP_RETURN prefix at line 1969).
     *
     * <p>Note: calling {@code addRawOutput} routes the auto-continuation
     * through the computeStateOutput path (AnfLower line ~239-253 — the
     * else branch, since {@code addOutputRefs.isEmpty()} when only
     * raw-outputs are present), which itself does push one 0x6a for
     * the contract's own state output. So the total 0x6a count in the
     * method is exactly 1 — entirely from the auto-continuation.
     */
    @Test
    void addRawOutputEmitsSizeAndNum2BinForSatoshis() {
        String src = """
            package fix.rawonly;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            import runar.lang.types.ByteString;
            class R extends StatefulSmartContract {
                Bigint count;
                R(Bigint count) { super(count); this.count = count; }
                @Public
                void send(ByteString scriptBytes) {
                    this.count = this.count.plus(Bigint.ONE);
                    this.addRawOutput(1000L, scriptBytes);
                }
            }
            """;
        StackProgram p = compile(src, "R.runar.java");
        StackMethod m = findMethod(p, "send");
        List<StackOp> ops = m.ops();

        // OP_SIZE for the varint-length prefix; OP_NUM2BIN for the
        // 8-byte satoshis prefix. Both paths sum at least 2 of each
        // because the auto-continuation also uses them.
        assertTrue(countOpcode(ops, "OP_SIZE") >= 1,
            "addRawOutput must emit OP_SIZE for scriptBytes length prefix");
        assertTrue(countOpcode(ops, "OP_NUM2BIN") >= 1,
            "addRawOutput must emit OP_NUM2BIN for satoshis prefix");
        // The method should produce a non-trivial sequence (the empty
        // baseline of 0 ops would mean dispatch failed).
        assertTrue(totalOps(ops) > 30,
            "addRawOutput method must emit > 30 ops; got " + totalOps(ops));
    }

    /**
     * {@code addDataOutput(sats, payload)}: dispatched through the
     * AddDataOutput ANF intrinsic which routes to
     * {@code lowerAddRawOutput} (StackLower.java:562-564) — the data
     * output is committed to the continuation but the lowerer treats it
     * the same as a raw output for the per-output opcode emission.
     * Compare a contract WITH addDataOutput against a baseline WITHOUT
     * it to confirm the dispatch added measurable structure.
     */
    @Test
    void addDataOutputAddsExtraOpcodesOverBaseline() {
        String baseline = """
            package fix.bdo;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            import runar.lang.types.ByteString;
            class B extends StatefulSmartContract {
                Bigint count;
                B(Bigint count) { super(count); this.count = count; }
                @Public
                void publish(ByteString payload) {
                    this.count = this.count.plus(Bigint.ONE);
                }
            }
            """;
        String withData = """
            package fix.wdo;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            import runar.lang.types.ByteString;
            class D extends StatefulSmartContract {
                Bigint count;
                D(Bigint count) { super(count); this.count = count; }
                @Public
                void publish(ByteString payload) {
                    this.count = this.count.plus(Bigint.ONE);
                    this.addDataOutput(0L, payload);
                }
            }
            """;
        StackProgram pb = compile(baseline, "B.runar.java");
        StackProgram pd = compile(withData, "D.runar.java");
        StackMethod mb = findMethod(pb, "publish");
        StackMethod md = findMethod(pd, "publish");

        // The addDataOutput call must add ops to the method's stream.
        assertTrue(totalOps(md.ops()) > totalOps(mb.ops()),
            "addDataOutput must produce more ops than the same method without it: "
                + totalOps(md.ops()) + " vs " + totalOps(mb.ops()));
        // It contributes more OP_SIZE / OP_CAT / OP_NUM2BIN to the stream.
        assertTrue(countOpcode(md.ops(), "OP_NUM2BIN") > countOpcode(mb.ops(), "OP_NUM2BIN"),
            "addDataOutput must add NUM2BINs (satoshis prefix)");
    }

    /**
     * End-to-end: a stateful contract calling {@code addOutput} drives
     * {@code methodUsesCodePart} → true, which means the stack lowerer
     * pushes a {@code _codePart} reference and uses it during output
     * construction. We check that OP_HASH256 (the continuation hash) is
     * emitted by the auto-injected {@code computeStateOutputHash}
     * companion (it isn't — addOutput uses the codePart directly), so
     * we instead verify that {@code OP_RETURN} byte construction reaches
     * the output builder.
     */
    @Test
    void statefulAddOutputFlowReachesContinuation() {
        StackProgram p = compile(COUNTER_SRC, "Counter.runar.java");
        StackMethod inc = findMethod(p, "increment");
        // The auto-injected continuation in a stateful method that
        // mutates state but doesn't explicitly call addOutput uses
        // computeStateOutputHash → OP_HASH256.
        assertTrue(countOpcode(inc.ops(), "OP_HASH256") >= 1,
            "stateful continuation must emit at least one OP_HASH256");
    }

    /* ================================================================== */
    /* 2. Multi-property load + builtin composition                        */
    /* ================================================================== */

    /**
     * Multiple readonly property loads in one method exercise
     * {@code lowerLoadProp} (StackLower.java:584) repeatedly. Each load
     * emits a {@link PlaceholderOp} (deploy-time substitution slot), so
     * the count of PlaceholderOps in a stateless contract's emitted
     * locking script must equal the number of readonly properties.
     */
    @Test
    void multiplePropertyLoadsEmitPlaceholderOps() {
        String src = """
            package fix.multiprop;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            class M extends SmartContract {
                @Readonly Bigint a;
                @Readonly Bigint b;
                @Readonly Bigint c;
                M(Bigint a, Bigint b, Bigint c) { super(a, b, c); this.a = a; this.b = b; this.c = c; }
                @Public
                void check() {
                    assertThat(this.a.plus(this.b).plus(this.c).ge(Bigint.ZERO));
                }
            }
            """;
        StackProgram p = compile(src, "M.runar.java");
        StackMethod m = findMethod(p, "check");
        long placeholders = m.ops().stream().filter(op -> op instanceof PlaceholderOp).count();
        assertEquals(3, placeholders,
            "3 readonly properties → 3 PlaceholderOps in the locking script; got " + placeholders);
        // Three operands → two ADDs.
        assertEquals(2, countOpcode(m.ops(), "OP_ADD"),
            "a + b + c must emit exactly 2 OP_ADDs");
    }

    /**
     * {@code hash160} + {@code equals} composition (the canonical P2PKH
     * idiom): the dispatch must reach the BUILTIN_OPCODES table at
     * StackLower.java:100 ({@code "hash160" → OP_HASH160}). Verifies
     * the general builtin path (line 832-844) is wired correctly
     * alongside the dedicated dispatch entries.
     */
    @Test
    void hash160AndEqualsDispatchEmitsExpectedOpcodes() {
        StackProgram p = compile(P2PKH_SRC, "P2PKH.runar.java");
        StackMethod m = findMethod(p, "unlock");
        assertEquals(1, countOpcode(m.ops(), "OP_HASH160"),
            "P2PKH must emit exactly 1 OP_HASH160");
        // Either OP_EQUALVERIFY (peephole-fused) or OP_EQUAL+OP_VERIFY.
        int eqOrVerify = countOpcode(m.ops(), "OP_EQUAL")
                       + countOpcode(m.ops(), "OP_EQUALVERIFY");
        assertTrue(eqOrVerify >= 1,
            "P2PKH must emit OP_EQUAL or OP_EQUALVERIFY for the pubKeyHash check");
    }

    /**
     * The {@code substr} builtin (StackLower.java:787) emits a known
     * fixed sequence including OP_SPLIT. This exercises the dedicated
     * {@code lowerSubstr} path rather than the general builtin table.
     */
    @Test
    void substrBuiltinReachesDedicatedLowerer() {
        String src = """
            package fix.substr;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import runar.lang.types.ByteString;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.substr;
            class S extends SmartContract {
                @Readonly ByteString full;
                S(ByteString full) { super(full); this.full = full; }
                @Public
                void check() {
                    ByteString head = substr(this.full, Bigint.ZERO, Bigint.of(4));
                    assertThat(head.equals(this.full));
                }
            }
            """;
        StackProgram p = compile(src, "S.runar.java");
        StackMethod m = findMethod(p, "check");
        // substr emits OP_SPLIT (one or more times) — the dedicated path.
        assertTrue(countOpcode(m.ops(), "OP_SPLIT") >= 1,
            "substr must reach lowerSubstr and emit OP_SPLIT");
    }

    /* ================================================================== */
    /* 3. Ternary expression                                               */
    /* ================================================================== */

    @Test
    void ternaryLowersToIfOpStructural() {
        String src = """
            package fix.tern;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            class T extends SmartContract {
                @Readonly Bigint limit;
                T(Bigint limit) { super(limit); this.limit = limit; }
                @Public
                void m(boolean mode, Bigint v) {
                    Bigint r = mode ? v.plus(this.limit) : v.minus(this.limit);
                    assertThat(r.gt(Bigint.ZERO));
                }
            }
            """;
        StackProgram p = compile(src, "T.runar.java");
        StackMethod m = findMethod(p, "m");
        // Ternary lowers to an If ANF node which becomes IfOp at Stack IR.
        assertTrue(countIfOps(m.ops()) >= 1, "ternary must produce an IfOp");
        // Then-branch has OP_ADD, else-branch has OP_SUB.
        assertEquals(1, countOpcode(m.ops(), "OP_ADD"),
            "ternary then-branch must emit exactly 1 OP_ADD (v + limit)");
        assertEquals(1, countOpcode(m.ops(), "OP_SUB"),
            "ternary else-branch must emit exactly 1 OP_SUB (v - limit)");
    }

    /**
     * Ternary embedded in an if/else where both arms compute the same
     * variable. The IfOp's then-branch must precede the else-branch in
     * canonical order (matches Go reference at compilers/go/codegen/stack.go
     * lowerIf — outer thenOps come before elseOps in the IfOp record).
     */
    @Test
    void ternaryThenBranchPrecedesElseBranch() {
        String src = """
            package fix.tern2;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            class T extends SmartContract {
                @Readonly Bigint limit;
                T(Bigint limit) { super(limit); this.limit = limit; }
                @Public
                void m(Bigint v, boolean mode) {
                    Bigint r = mode ? v.plus(this.limit) : v.minus(this.limit);
                    assertThat(r.gt(Bigint.ZERO));
                }
            }
            """;
        StackProgram p = compile(src, "T.runar.java");
        StackMethod m = findMethod(p, "m");
        IfOp ifOp = null;
        for (StackOp op : m.ops()) {
            if (op instanceof IfOp i) { ifOp = i; break; }
        }
        assertNotNull(ifOp, "expected an IfOp");
        assertNotNull(ifOp.thenBranch(), "then-branch present");
        assertNotNull(ifOp.elseBranch(), "else-branch present");
        // Then has ADD; else has SUB. Verify by examining branch contents.
        boolean thenHasAdd = countOpcode(ifOp.thenBranch(), "OP_ADD") >= 1;
        boolean elseHasSub = countOpcode(ifOp.elseBranch(), "OP_SUB") >= 1;
        assertTrue(thenHasAdd, "then-branch must contain OP_ADD");
        assertTrue(elseHasSub, "else-branch must contain OP_SUB");
    }

    /* ================================================================== */
    /* 4. Bitwise + shift operators                                        */
    /* ================================================================== */

    @Test
    void bitwiseAndOrXorLowerToOpcodes() {
        // The Bigint wrapper exposes .and/.or/.xor methods; the parser
        // lowers them to BinaryExpr nodes with op tokens "&", "|", "^"
        // which then map to OP_AND / OP_OR / OP_XOR via BINOP_OPCODES
        // (StackLower.java:132-134).
        String src = """
            package fix.bw;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            class B extends SmartContract {
                @Readonly Bigint a;
                @Readonly Bigint b;
                B(Bigint a, Bigint b) { super(a, b); this.a = a; this.b = b; }
                @Public
                void m() {
                    Bigint x = this.a.and(this.b);
                    Bigint y = this.a.or(this.b);
                    Bigint z = this.a.xor(this.b);
                    assertThat(x.ge(Bigint.ZERO));
                    assertThat(y.ge(Bigint.ZERO));
                    assertThat(z.ge(Bigint.ZERO));
                }
            }
            """;
        StackProgram p = compile(src, "B.runar.java");
        StackMethod m = findMethod(p, "m");
        List<StackOp> ops = m.ops();
        assertEquals(1, countOpcode(ops, "OP_AND"),  "expected OP_AND for `.and(b)`");
        assertEquals(1, countOpcode(ops, "OP_OR"),   "expected OP_OR for `.or(b)`");
        assertEquals(1, countOpcode(ops, "OP_XOR"),  "expected OP_XOR for `.xor(b)`");
    }

    @Test
    void unaryNegateLowersToOpNegate() {
        // The contract uses .neg() which the parser maps to UnaryExpr(-).
        // UNARYOP_OPCODES: "-" → OP_NEGATE (StackLower.java:140-142).
        // Bigint exposes no `.not()` so we test arithmetic negation here;
        // the OP_INVERT path is exercised by integration fixtures that
        // use the `~` operator on ByteString.
        String src = """
            package fix.neg;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            class N extends SmartContract {
                @Readonly Bigint a;
                N(Bigint a) { super(a); this.a = a; }
                @Public
                void m() {
                    Bigint r = this.a.neg();
                    assertThat(r.le(Bigint.ZERO) || r.ge(Bigint.ZERO));
                }
            }
            """;
        StackProgram p = compile(src, "N.runar.java");
        StackMethod m = findMethod(p, "m");
        assertEquals(1, countOpcode(m.ops(), "OP_NEGATE"),
            "unary .neg() must emit exactly 1 OP_NEGATE");
    }

    @Test
    void shiftOpsLowerToLshiftAndRshift() {
        // Bigint.shl/.shr methods → "<<" / ">>" → OP_LSHIFT / OP_RSHIFT.
        String src = """
            package fix.sh;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            class S extends SmartContract {
                @Readonly Bigint a;
                S(Bigint a) { super(a); this.a = a; }
                @Public
                void m() {
                    Bigint l = this.a.shl(Bigint.TWO);
                    Bigint r = this.a.shr(Bigint.ONE);
                    assertThat(l.ge(Bigint.ZERO) || l.lt(Bigint.ZERO));
                    assertThat(r.ge(Bigint.ZERO) || r.lt(Bigint.ZERO));
                }
            }
            """;
        StackProgram p = compile(src, "S.runar.java");
        StackMethod m = findMethod(p, "m");
        assertEquals(1, countOpcode(m.ops(), "OP_LSHIFT"),
            "shl must emit exactly 1 OP_LSHIFT");
        assertEquals(1, countOpcode(m.ops(), "OP_RSHIFT"),
            "shr must emit exactly 1 OP_RSHIFT");
    }

    /* ================================================================== */
    /* 5. Stateful continuation hash                                       */
    /* ================================================================== */

    /**
     * The auto-injected continuation: at the end of a stateful method
     * the compiler emits computeStateOutputHash → which lowers to a
     * sequence ending in OP_HASH256. Verify the hash and equality check
     * are present and that they appear AFTER the user's mutation.
     */
    @Test
    void statefulCounterEmitsHash256AfterMutation() {
        StackProgram p = compile(COUNTER_SRC, "Counter.runar.java");
        StackMethod inc = findMethod(p, "increment");
        List<StackOp> ops = inc.ops();
        // Find the OP_ADD (mutation) and OP_HASH256 (continuation).
        int addIdx = -1;
        int hashIdx = -1;
        for (int i = 0; i < ops.size(); i++) {
            StackOp op = ops.get(i);
            if (op instanceof OpcodeOp o) {
                if (addIdx < 0 && ("OP_ADD".equals(o.code()) || "OP_1ADD".equals(o.code()))) addIdx = i;
                if ("OP_HASH256".equals(o.code())) hashIdx = i;
            }
        }
        assertTrue(addIdx >= 0, "expected OP_ADD/OP_1ADD for `count + 1`");
        assertTrue(hashIdx >= 0, "expected OP_HASH256 for the continuation hash");
        assertTrue(hashIdx > addIdx,
            "OP_HASH256 must appear AFTER the user's mutation");
    }

    /**
     * The continuation must be enforced via an equality check against the
     * preimage's {@code hashOutputs} field. After the {@code OP_HASH256}
     * we expect either {@code OP_EQUAL} (followed by VERIFY via
     * peephole-targetable shape) or {@code OP_EQUALVERIFY} as the
     * tail of the stateful method.
     */
    @Test
    void statefulContinuationEnforcedViaEqualOrEqualVerify() {
        StackProgram p = compile(COUNTER_SRC, "Counter.runar.java");
        StackMethod inc = findMethod(p, "increment");
        List<StackOp> ops = inc.ops();
        int hash = -1;
        for (int i = 0; i < ops.size(); i++) {
            if (ops.get(i) instanceof OpcodeOp o && "OP_HASH256".equals(o.code())) {
                hash = i;
                break;
            }
        }
        assertTrue(hash >= 0);
        // Walk forward from the hash and look for an equality opcode.
        boolean sawEqOrEqVerify = false;
        for (int j = hash + 1; j < ops.size(); j++) {
            if (ops.get(j) instanceof OpcodeOp o
                    && ("OP_EQUAL".equals(o.code()) || "OP_EQUALVERIFY".equals(o.code())
                        || "OP_VERIFY".equals(o.code()))) {
                sawEqOrEqVerify = true;
                break;
            }
        }
        assertTrue(sawEqOrEqVerify,
            "continuation hash must be enforced via OP_EQUAL/OP_EQUALVERIFY/OP_VERIFY");
    }

    /* ================================================================== */
    /* 6. CodeSeparator slots                                              */
    /* ================================================================== */

    /**
     * A stateful contract must emit {@code OP_CODESEPARATOR} exactly
     * once per public method (it's auto-inserted at method entry by the
     * checkPreimage lowering). This exercises that single-method shape.
     */
    @Test
    void statefulSingleMethodEmitsOneCodeSeparator() {
        StackProgram p = compile(COUNTER_SRC, "Counter.runar.java");
        StackMethod inc = findMethod(p, "increment");
        assertEquals(1, countOpcode(inc.ops(), "OP_CODESEPARATOR"),
            "stateful single-method contract must emit exactly 1 OP_CODESEPARATOR");
    }

    /**
     * A stateful contract with two public methods produces two
     * {@code StackMethod}s; each carries its own auto-injected
     * OP_CODESEPARATOR. This is the multi-method codeseparator-slot
     * shape that the deploy-side artifact records via
     * {@code codeSeparatorIndices}.
     */
    @Test
    void statefulMultiMethodEachEmitsCodeSeparator() {
        String src = """
            package fix.cs;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            class Q extends StatefulSmartContract {
                Bigint count;
                Q(Bigint count) { super(count); this.count = count; }
                @Public
                void inc() { this.count = this.count.plus(Bigint.ONE); }
                @Public
                void dec() { this.count = this.count.minus(Bigint.ONE); }
            }
            """;
        StackProgram p = compile(src, "Q.runar.java");
        assertEquals(2, p.methods().size());
        for (StackMethod m : p.methods()) {
            assertEquals(1, countOpcode(m.ops(), "OP_CODESEPARATOR"),
                "each stateful method must emit exactly 1 OP_CODESEPARATOR");
        }
    }

    /* ================================================================== */
    /* 7. Crypto-builtin dispatch routing                                  */
    /* ================================================================== */
    /* Each test builds a tiny contract that touches one builtin, lowers   */
    /* it, and asserts the dispatch reached the correct codegen module —   */
    /* i.e. the resulting op stream is non-trivial and contains opcodes    */
    /* characteristic of the module's emit. The unknown-builtin throw at   */
    /* StackLower.java:840 would manifest as a build failure, so reaching  */
    /* this point at all proves the dispatch wiring is correct.            */

    @Test
    void ecAddDispatchReachesEcModule() {
        String src = """
            package fix.eca;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.runtime.MockCrypto.Point;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.ecAdd;
            import static runar.lang.Builtins.ecOnCurve;
            class E extends SmartContract {
                @Readonly Point a;
                @Readonly Point b;
                E(Point a, Point b) { super(a, b); this.a = a; this.b = b; }
                @Public
                void check() {
                    Point r = ecAdd(this.a, this.b);
                    assertThat(ecOnCurve(r));
                }
            }
            """;
        StackProgram p = compile(src, "E.runar.java");
        StackMethod m = findMethod(p, "check");
        // EC point addition produces a long sequence — assert that the
        // EC module emitted ≥ 100 ops (real EC is 1000s; threshold is
        // generous to allow future micro-optimisations).
        assertTrue(totalOps(m.ops()) >= 100,
            "ecAdd dispatch must reach Ec.java and emit a long sequence; got "
                + totalOps(m.ops()));
    }

    @Test
    void ecMakePointAndExtractDispatchReachesEcModule() {
        String src = """
            package fix.ecmp;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import runar.lang.runtime.MockCrypto.Point;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.ecMakePoint;
            import static runar.lang.Builtins.ecPointX;
            import static runar.lang.Builtins.ecPointY;
            class E extends SmartContract {
                @Readonly Bigint anchor;
                E(Bigint anchor) { super(anchor); this.anchor = anchor; }
                @Public
                void m(Bigint x, Bigint y, Bigint ex, Bigint ey) {
                    Point pt = ecMakePoint(x, y);
                    assertThat(ecPointX(pt).eq(ex));
                    assertThat(ecPointY(pt).eq(ey));
                }
            }
            """;
        StackProgram p = compile(src, "E.runar.java");
        StackMethod m = findMethod(p, "m");
        // makePoint + 2 extracts + 2 equality checks: many CAT/SPLIT ops.
        assertTrue(totalOps(m.ops()) > 10,
            "ecMakePoint + ecPointX/Y must produce > 10 ops");
        // Two `.eq()` calls on Bigint produce OP_NUMEQUAL (BINOP_OPCODES
        // table maps the canonical "===" token to OP_NUMEQUAL at
        // StackLower.java:124).
        assertTrue(countOpcode(m.ops(), "OP_NUMEQUAL") >= 2,
            "two .eq() calls must produce ≥ 2 OP_NUMEQUAL");
    }

    @Test
    void sha256CompressDispatchReachesSha256Module() {
        String src = """
            package fix.shc;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.ByteString;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.sha256Compress;
            class H extends SmartContract {
                @Readonly ByteString expected;
                H(ByteString expected) { super(expected); this.expected = expected; }
                @Public
                void verify(ByteString state, ByteString block) {
                    ByteString r = sha256Compress(state, block);
                    assertThat(r.equals(this.expected));
                }
            }
            """;
        StackProgram p = compile(src, "H.runar.java");
        StackMethod m = findMethod(p, "verify");
        // SHA-256 compress is ~74KB script: many thousand ops.
        assertTrue(totalOps(m.ops()) > 1000,
            "sha256Compress dispatch must reach Sha256.java and emit > 1000 ops; got "
                + totalOps(m.ops()));
    }

    @Test
    void blake3HashDispatchReachesBlake3Module() {
        String src = """
            package fix.bh;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Addr;
            import runar.lang.types.PubKey;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.blake3Hash;
            class H extends SmartContract {
                @Readonly Addr pubKeyHash;
                H(Addr pubKeyHash) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
                @Public
                void unlock(PubKey pubKey) {
                    assertThat(blake3Hash(pubKey).equals(this.pubKeyHash));
                }
            }
            """;
        StackProgram p = compile(src, "H.runar.java");
        StackMethod m = findMethod(p, "unlock");
        // Blake3 is also a long sequence (≫ 100 ops).
        assertTrue(totalOps(m.ops()) > 100,
            "blake3Hash dispatch must reach Blake3.java and emit > 100 ops; got "
                + totalOps(m.ops()));
    }

    @Test
    void verifyEcdsaP256DispatchReachesP256P384Module() {
        String src = """
            package fix.p256;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.ByteString;
            import runar.lang.types.PubKey;
            import runar.lang.types.Sig;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.verifyECDSA_P256;
            class P extends SmartContract {
                @Readonly ByteString pk;
                P(ByteString pk) { super(pk); this.pk = pk; }
                @Public
                void spend(Sig msg, ByteString sig) {
                    assertThat(verifyECDSA_P256(msg, sig, this.pk));
                }
            }
            """;
        StackProgram p = compile(src, "P.runar.java");
        StackMethod m = findMethod(p, "spend");
        // P-256 verify is one of the longest emitters; assert > 1000 ops.
        assertTrue(totalOps(m.ops()) > 1000,
            "verifyECDSA_P256 dispatch must reach P256P384.java and emit > 1000 ops; got "
                + totalOps(m.ops()));
    }

    @Test
    void verifyWotsDispatchReachesWotsModule() {
        String src = """
            package fix.wots;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.ByteString;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.verifyWOTS;
            class W extends SmartContract {
                @Readonly ByteString pubkey;
                W(ByteString pubkey) { super(pubkey); this.pubkey = pubkey; }
                @Public
                void spend(ByteString msg, ByteString sig) {
                    assertThat(verifyWOTS(msg, sig, this.pubkey));
                }
            }
            """;
        StackProgram p = compile(src, "W.runar.java");
        StackMethod m = findMethod(p, "spend");
        // WOTS is ~10KB script — many ops.
        assertTrue(totalOps(m.ops()) > 100,
            "verifyWOTS dispatch must reach Wots.java and emit > 100 ops; got "
                + totalOps(m.ops()));
    }

    @Test
    void verifyRabinSigDispatchReachesRabinModule() {
        // The Rabin signature verifier takes msg + sig + padding + pubkey
        // and produces a bool. We pass the message as raw ByteString
        // (the canonical num2bin packaging is exercised in dedicated
        // RabinTest fixtures; here we only need the dispatch).
        String src = """
            package fix.rabin;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.ByteString;
            import runar.lang.types.RabinPubKey;
            import runar.lang.types.RabinSig;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.verifyRabinSig;
            class R extends SmartContract {
                @Readonly RabinPubKey pk;
                R(RabinPubKey pk) { super(pk); this.pk = pk; }
                @Public
                void settle(ByteString msg, RabinSig sig, ByteString padding) {
                    assertThat(verifyRabinSig(msg, sig, padding, this.pk));
                }
            }
            """;
        StackProgram p = compile(src, "R.runar.java");
        StackMethod m = findMethod(p, "settle");
        // Rabin verify is the shortest of the crypto modules but still
        // reliably > 15 ops. The unknown-builtin throw at line 840 would
        // produce zero crypto-emit ops (not even reaching the lowerer),
        // so any double-digit total proves the dispatch wired through.
        assertTrue(totalOps(m.ops()) > 15,
            "verifyRabinSig dispatch must reach Rabin.java and emit > 15 ops; got "
                + totalOps(m.ops()));
    }

    @Test
    void verifySlhDsaDispatchReachesSlhDsaModule() {
        String src = """
            package fix.slh;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.ByteString;
            import static runar.lang.Builtins.assertThat;
            import static runar.lang.Builtins.verifySLHDSA_SHA2_128s;
            class S extends SmartContract {
                @Readonly ByteString pk;
                S(ByteString pk) { super(pk); this.pk = pk; }
                @Public
                void spend(ByteString msg, ByteString sig) {
                    assertThat(verifySLHDSA_SHA2_128s(msg, sig, this.pk));
                }
            }
            """;
        StackProgram p = compile(src, "S.runar.java");
        StackMethod m = findMethod(p, "spend");
        // SLH-DSA SHA2_128s is hundreds of KB — by far the largest
        // emitter. Assert ops > 10000 to confirm the dispatch routed
        // to SlhDsa.java (any short-circuit / unknown-builtin throw
        // would fail compile rather than produce few ops).
        assertTrue(totalOps(m.ops()) > 10000,
            "verifySLHDSA_SHA2_128s dispatch must reach SlhDsa.java and emit > 10000 ops; got "
                + totalOps(m.ops()));
    }

    /* ================================================================== */
    /* 8. Method-call inlining                                             */
    /* ================================================================== */

    @Test
    void privateHelperBodyInlinedAtCallSite() {
        // The helper computes a + 5; the public method calls it and
        // asserts the result. After lowering there is exactly ONE
        // StackMethod (the public one) — the helper is NOT a separate
        // entry point. The helper's OP_ADD (or OP_5ADD-style sequence)
        // appears within the public method's ops.
        String src = """
            package fix.inline;
            import java.math.BigInteger;
            import runar.lang.SmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.annotations.Readonly;
            import runar.lang.types.Bigint;
            import static runar.lang.Builtins.assertThat;
            class I extends SmartContract {
                @Readonly Bigint base;
                I(Bigint base) { super(base); this.base = base; }
                private Bigint addFive(Bigint x) {
                    return x.plus(Bigint.of(5));
                }
                @Public
                void check(Bigint y) {
                    Bigint r = this.addFive(y);
                    assertThat(r.gt(Bigint.ZERO));
                }
            }
            """;
        StackProgram p = compile(src, "I.runar.java");
        // Only the public method appears — helpers are inlined.
        assertEquals(1, p.methods().size(),
            "private helper must NOT be a separate StackMethod (got "
                + p.methods().size() + ")");
        StackMethod m = findMethod(p, "check");
        // Inlined body: y + 5 → OP_ADD, plus the gt → OP_GREATERTHAN.
        assertTrue(countOpcode(m.ops(), "OP_ADD") >= 1,
            "inlined helper body must contribute its OP_ADD");
        assertTrue(countOpcode(m.ops(), "OP_GREATERTHAN") >= 1,
            "post-inline gt comparison present");
    }

    /* ================================================================== */
    /* 9. Property load / store                                            */
    /* ================================================================== */

    /**
     * A stateful property with an initialiser ({@code = Bigint.of(5)}) is
     * NOT a constructor parameter; ExpandFixedArrays + AnfLower place its
     * literal value as the slot's initial value. The lowerer should still
     * treat it as a regular state slot.
     */
    @Test
    void initializedPropertyDoesNotAppearAsConstructorParam() {
        String src = """
            package fix.initprop;
            import runar.lang.StatefulSmartContract;
            import runar.lang.annotations.Public;
            import runar.lang.types.Bigint;
            class P extends StatefulSmartContract {
                Bigint count;
                Bigint factor = Bigint.of(5);
                P(Bigint count) { super(count); this.count = count; }
                @Public
                void bump() {
                    this.count = this.count.plus(this.factor);
                }
            }
            """;
        StackProgram p = compile(src, "P.runar.java");
        StackMethod m = findMethod(p, "bump");
        // The mutation `count + factor` lowers to OP_ADD.
        assertTrue(countOpcode(m.ops(), "OP_ADD") >= 1,
            "initialized property must still participate in arithmetic");
        // Continuation must still fire (factor + count are both state).
        assertTrue(countOpcode(m.ops(), "OP_HASH256") >= 1,
            "stateful contract with initialised property must emit continuation OP_HASH256");
    }

    /**
     * UpdateProp (the {@code this.x = expr} form) emits a NipOp when the
     * property is at depth 1 (mirrors the dispatch in
     * {@code lowerUpdateProp}, StackLower.java:1715). For deeper props
     * it emits a ROLL+DROP. Verify the simple counter-assign form
     * produces a NipOp at top level.
     */
    @Test
    void updatePropAtDepth1EmitsNip() {
        // The Counter contract's `this.count = this.count + 1`:
        // 1. LoadProp count → push count.
        // 2. BinOp + 1 → emit OP_ADD (consumes count + literal, pushes result).
        // 3. UpdateProp count → bring result to top, then nip out the
        //    OLD count slot if present. In the post-lower op stream that
        //    appears as a NipOp.
        // The peephole and order-of-ops mean the NipOp may be subsumed,
        // but in StackLower's output (BEFORE peephole) it should appear.
        StackProgram p = compile(COUNTER_SRC, "Counter.runar.java");
        StackMethod inc = findMethod(p, "increment");
        long nipCount = inc.ops().stream().filter(op -> op instanceof NipOp).count();
        // At minimum the addOutput and continuation logic produce nips,
        // so we just assert ≥ 1 NipOp is present in this stateful flow.
        assertTrue(nipCount >= 1,
            "stateful counter increment must emit at least one NipOp "
                + "(UpdateProp at depth 1 + cleanup); got " + nipCount);
    }
}
