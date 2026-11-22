package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.ast.ContractNode;

/**
 * D25: the contract-level continuation binding ({@link ContinuationBinding}):
 * classification, the SINGLE default, the hidden spent-outpoint field, the
 * diagnostics, and the {@code --ir} check. Port of
 * {@code packages/runar-compiler/src/__tests__/d25-continuation-binding.test.ts}.
 */
class D25ContinuationBindingTest {

    private static final String FIELD = ContinuationBinding.TWIN_BINDING_FIELD;

    private static final String STATEFUL =
        "import { StatefulSmartContract, assert, checkSig, extractAmount, extractOutputHash, hash256 } from 'runar-lang';\n"
        + "import type { PubKey, Sig, Sha256 } from 'runar-lang';\n";

    private static String counter(String incDirective, String decDirective) {
        return STATEFUL + "\nclass Counter extends StatefulSmartContract {\n"
            + "  count: bigint;\n"
            + "  constructor(count: bigint) { super(count); this.count = count; }\n"
            + "  " + incDirective + "\n"
            + "  public increment() { this.count++; }\n"
            + "  " + decDirective + "\n"
            + "  public decrement() { assert(this.count > 0n); this.count--; }\n"
            + "}\n";
    }

    private static final String MIXED = STATEFUL + "\nclass MixedPot extends StatefulSmartContract {\n"
        + "  count: bigint;\n"
        + "  constructor(count: bigint) { super(count); this.count = count; }\n"
        + "  public increment() { this.count++; }\n"
        + "  public bump() { this.addOutput(extractAmount(this.txPreimage), this.count + 1n); }\n"
        + "}\n";

    private record Compiled(AnfProgram anf, List<String> warnings) {}

    /** The production source pipeline (Cli#compileSource), fold-OFF. */
    private static ContractNode parse(String src, String name) {
        try {
            return ParserDispatch.parse(src, name + ".runar.ts");
        } catch (ParserDispatch.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Compiled ok(String src, String name) {
        ContractNode c = parse(src, name);
        List<String> warnings = Validate.run(c);
        Typecheck.run(c);
        c = ExpandFixedArrays.run(ContinuationBinding.apply(c));
        return new Compiled(Cli.optimizeAnf(AnfLower.run(c), true), warnings);
    }

    private static List<String> errors(String src, String name) {
        return Validate.runCollecting(parse(src, name)).errors();
    }

    private static AnfMethod method(AnfProgram p, String name) {
        return p.methods().stream().filter(m -> m.name().equals(name)).findFirst().orElseThrow();
    }

    /** The ABI sigHashType (null = the default ALL|FORKID). */
    private static Integer abiMode(Compiled r, String m) {
        return method(r.anf(), m).sighashType();
    }

    private static List<String> stateFields(Compiled r) {
        return r.anf().properties().stream().filter(p -> !p.readonly()).map(AnfProperty::name).toList();
    }

    private static void walk(List<AnfBinding> bs, java.util.function.Consumer<AnfBinding> f) {
        for (AnfBinding b : bs) {
            f.accept(b);
            if (b.value() instanceof If iff) {
                if (iff.thenBranch() != null) walk(iff.thenBranch(), f);
                if (iff.elseBranch() != null) walk(iff.elseBranch(), f);
            } else if (b.value() instanceof Loop l && l.body() != null) {
                walk(l.body(), f);
            }
        }
    }

    /** compileFromANF's frontend rules: the --ir loader. */
    private static void loadIr(AnfProgram p) {
        AnfLoader.parse(Jcs.stringify(p));
    }

    // ---- class 1 ------------------------------------------------------------

    @Test
    void class1DefaultsEveryContinuationMethodToSingleAndDropsTheChangeParams() {
        Compiled r = ok(counter("", ""), "Counter");
        assertEquals(0x43, abiMode(r, "increment"));
        assertEquals(0x43, abiMode(r, "decrement"));
        assertEquals(List.of("count"), stateFields(r));
        List<String> params = method(r.anf(), "increment").params().stream().map(p -> p.name()).toList();
        assertEquals(List.of("_newAmount", "txPreimage"), params);
    }

    @Test
    void class1MapsAllAcpToSingleAcp() {
        String d = "/** @sighash ALL|ANYONECANPAY|FORKID */";
        assertEquals(0xc3, abiMode(ok(counter(d, d), "Counter"), "increment"));
    }

    @Test
    void class1KeepsAnExplicitSingleAcp() {
        String d = "/** @sighash SINGLE|ANYONECANPAY|FORKID */";
        assertEquals(0xc3, abiMode(ok(counter(d, ""), "Counter"), "increment"));
    }

    @Test
    void class1RefusesAnExplicitAllSibling() {
        List<String> errs = errors(counter("", "/** @sighash ALL|FORKID */"), "Counter");
        assertTrue(errs.stream().anyMatch(e -> e.contains("method 'decrement': @sighash ALL|FORKID")
            && e.contains("reopens twin-input theft")), errs.toString());
    }

    @Test
    void class1TerminalMethodKeepsAll() {
        String src = STATEFUL + "\nclass Box extends StatefulSmartContract {\n"
            + "  count: bigint;\n  readonly owner: PubKey;\n"
            + "  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }\n"
            + "  public bump() { this.count++; }\n"
            + "  public close(sig: Sig) { assert(checkSig(sig, this.owner)); }\n}\n";
        Compiled r = ok(src, "Box");
        assertEquals(0x43, abiMode(r, "bump"));
        assertNull(abiMode(r, "close"));
    }

    // ---- class 2 ------------------------------------------------------------

    @Test
    void class2AppendsAZeroSha256FieldLastOutsideTheConstructorAbi() {
        Compiled r = ok(MIXED, "MixedPot");
        assertEquals(List.of("count", FIELD), stateFields(r));
        assertEquals(List.of("count"), method(r.anf(), "constructor").params().stream().map(p -> p.name()).toList());
        AnfProperty prop = r.anf().properties().get(r.anf().properties().size() - 1);
        assertEquals("Sha256", prop.type());
        assertEquals("00".repeat(32), ((BytesConst) prop.initialValue()).hex());
        // Every method keeps ALL: no blending of SINGLE and the field.
        assertNull(abiMode(r, "increment"));
        assertNull(abiMode(r, "bump"));
    }

    @Test
    void class2WritesTheOutpointHashInTheAutoContinuationAndAppendsItToAddOutput() {
        Compiled r = ok(MIXED, "MixedPot");
        List<String> writes = new ArrayList<>();
        walk(method(r.anf(), "increment").body(), b -> {
            if (b.value() instanceof UpdateProp up) writes.add(up.name());
        });
        assertTrue(writes.contains(FIELD), writes.toString());
        List<AddOutput> outs = new ArrayList<>();
        walk(method(r.anf(), "bump").body(), b -> {
            if (b.value() instanceof AddOutput ao) outs.add(ao);
        });
        assertEquals(1, outs.size());
        assertEquals(2, outs.get(0).stateValues().size());
    }

    @Test
    void class2MutateOnlyReadingExtractOutputHashIsBound() {
        String src = STATEFUL + "\nclass Peek extends StatefulSmartContract {\n"
            + "  count: bigint;\n"
            + "  constructor(count: bigint) { super(count); this.count = count; }\n"
            + "  public bump(h: Sha256) { assert(extractOutputHash(this.txPreimage) !== h); this.count++; }\n}\n";
        Compiled r = ok(src, "Peek");
        assertNull(abiMode(r, "bump"));
        assertEquals(List.of("count", FIELD), stateFields(r));
    }

    @Test
    void class2TheFieldNameIsReserved() {
        String src = STATEFUL + "\nclass X extends StatefulSmartContract {\n"
            + "  _spentOutpointHash: bigint;\n"
            + "  constructor(_spentOutpointHash: bigint) { super(_spentOutpointHash); this._spentOutpointHash = _spentOutpointHash; }\n"
            + "  public bump() { this._spentOutpointHash++; }\n}\n";
        List<String> errs = errors(src, "X");
        assertTrue(errs.stream().anyMatch(e -> e.contains("'_spentOutpointHash' is reserved")), errs.toString());
    }

    // ---- class 3 ------------------------------------------------------------

    private static String pot(String body) {
        return STATEFUL + "\nclass Pot extends StatefulSmartContract {\n"
            + "  count: bigint;\n  readonly owner: PubKey;\n"
            + "  constructor(count: bigint, owner: PubKey) { super(count, owner); this.count = count; this.owner = owner; }\n"
            + "  public bump(sig: Sig) { " + body + " }\n}\n";
    }

    @Test
    void class3WarnsOnAnUnsignedValueConservingAddOutput() {
        Compiled r = ok(pot("this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot");
        assertEquals(1, r.warnings().stream().filter(w -> w.contains("twin-input aliasing")).count(), r.warnings().toString());
        assertEquals(List.of("count"), stateFields(r));
        assertNull(abiMode(r, "bump"));
    }

    @Test
    void class3FollowsALocalInitialisedFromExtractAmount() {
        Compiled r = ok(pot("const v: bigint = extractAmount(this.txPreimage); this.addOutput(v, this.count + 1n);"), "Pot");
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("twin-input aliasing")), r.warnings().toString());
    }

    @Test
    void class3DoesNotWarnWhenTheMethodChecksASignature() {
        Compiled r = ok(pot("assert(checkSig(sig, this.owner)); this.addOutput(extractAmount(this.txPreimage), this.count + 1n);"), "Pot");
        assertFalse(r.warnings().stream().anyMatch(w -> w.contains("twin-input aliasing")), r.warnings().toString());
    }

    // ---- --ir ---------------------------------------------------------------

    @Test
    void irAcceptsTheFrontendIrOfEveryClass() {
        loadIr(ok(counter("", ""), "Counter").anf());
        loadIr(ok(MIXED, "MixedPot").anf());
    }

    @Test
    void irRefusesAMutateOnlyProgramWhoseContinuationCommitsUnderAll() {
        AnfProgram p = ok(counter("", ""), "Counter").anf();
        List<AnfMethod> ms = new ArrayList<>();
        for (AnfMethod m : p.methods()) {
            ms.add(m.name().equals("decrement") ? new AnfMethod(m.name(), m.params(), m.body(), m.isPublic(), null) : m);
        }
        RuntimeException e = assertThrows(RuntimeException.class, () -> loadIr(p.withMethods(ms)));
        assertTrue(e.getMessage().contains("IR validation"), e.getMessage());
    }

    @Test
    void irRefusesAMixedProgramWithoutTheBindingField() {
        // The pre-D25 IR: no field, no write, no extra add_output value, no hash chain.
        AnfProgram p = ok(MIXED, "MixedPot").anf();
        List<AnfProperty> props = p.properties().stream().filter(x -> !x.name().equals(FIELD)).toList();
        List<AnfMethod> ms = new ArrayList<>();
        for (AnfMethod m : p.methods()) {
            Map<String, AnfValue> byName = new HashMap<>();
            walk(m.body(), b -> byName.put(b.name(), b.value()));
            Set<String> drop = new HashSet<>();
            List<AnfBinding> body = new ArrayList<>();
            for (AnfBinding b : m.body()) {
                String hash = null;
                if (b.value() instanceof UpdateProp up && up.name().equals(FIELD)) {
                    drop.add(b.name());
                    hash = up.value();
                } else if (b.value() instanceof AddOutput ao) {
                    List<String> sv = new ArrayList<>(ao.stateValues());
                    hash = sv.remove(sv.size() - 1);
                    b = new AnfBinding(b.name(), new AddOutput(ao.satoshis(), sv, ao.preimage()), b.sourceLoc());
                }
                if (hash != null) {
                    String outpoint = ((Call) byName.get(hash)).args().get(0);
                    String pre = ((Call) byName.get(outpoint)).args().get(0);
                    drop.add(hash);
                    drop.add(outpoint);
                    drop.add(pre);
                }
                body.add(b);
            }
            body.removeIf(b -> drop.contains(b.name()));
            ms.add(m.withBody(body));
        }
        AnfProgram plain = new AnfProgram(p.contractName(), props, ms, p.parentClass());
        RuntimeException e = assertThrows(RuntimeException.class, () -> loadIr(plain));
        assertTrue(e.getMessage().contains("not bound to its input"), e.getMessage());
    }

    @Test
    void irRefusesAnAddOutputWhoseLastStateValueIsNotTheOutpointHash() {
        AnfProgram p = ok(MIXED, "MixedPot").anf();
        List<AnfMethod> ms = new ArrayList<>();
        for (AnfMethod m : p.methods()) {
            if (!m.name().equals("bump")) {
                ms.add(m);
                continue;
            }
            List<AnfBinding> body = new ArrayList<>();
            for (AnfBinding b : m.body()) {
                if (b.value() instanceof AddOutput ao) {
                    List<String> sv = List.of(ao.stateValues().get(0), ao.stateValues().get(0));
                    b = new AnfBinding(b.name(), new AddOutput(ao.satoshis(), sv, ao.preimage()), b.sourceLoc());
                }
                body.add(b);
            }
            ms.add(m.withBody(body));
        }
        RuntimeException e = assertThrows(RuntimeException.class, () -> loadIr(p.withMethods(ms)));
        assertTrue(e.getMessage().contains("every add_output must carry"), e.getMessage());
    }
}
