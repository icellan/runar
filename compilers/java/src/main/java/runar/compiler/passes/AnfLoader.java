package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import runar.compiler.ir.anf.AddDataOutput;
import runar.compiler.ir.anf.AddOutput;
import runar.compiler.ir.anf.AddRawOutput;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfParam;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfProperty;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.ArrayLiteral;
import runar.compiler.ir.anf.Assert;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.CheckPreimage;
import runar.compiler.ir.anf.ConstValue;
import runar.compiler.ir.anf.DeserializeState;
import runar.compiler.ir.anf.GetStateScript;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.LoadParam;
import runar.compiler.ir.anf.LoadProp;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.MethodCall;
import runar.compiler.ir.anf.RawScript;
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;
import runar.compiler.ir.UnknownAnfKindError;

/**
 * Hand-rolled loader for canonical ANF JSON → {@link AnfProgram}.
 *
 * <p>Used by the {@code --ir <path> --hex} mode to skip parse/validate/
 * typecheck/anf-lower and go straight to stack lowering. Accepts the same
 * canonical shape that {@link runar.compiler.canonical.Jcs} emits.
 */
public final class AnfLoader {

    private AnfLoader() {}

    public static AnfProgram parse(String json) {
        // DoS-bound guards run before the hand-rolled JSON parser so a
        // malicious payload cannot exhaust memory (size) or the JVM
        // thread stack (nesting). BUG-008 follow-up.
        IRInputLimits.assertIRBytesUnderLimit(json);
        IRInputLimits.assertIRNestingUnderLimit(json);

        JsonParser p = new JsonParser(json);
        Object root = p.parseValue();
        p.skipWs();
        if (p.pos != p.src.length()) throw new RuntimeException("trailing garbage in ANF JSON");
        if (!(root instanceof Map<?, ?> map)) {
            throw new RuntimeException("ANF JSON root is not an object");
        }
        return toProgram(map);
    }

    /**
     * The loader's JSON reader, for tests that read shared JSON corpora
     * (objects are {@code Map}, arrays {@code List}, numbers as parsed here).
     */
    static Object parseJsonTree(String json) {
        JsonParser p = new JsonParser(json);
        Object root = p.parseValue();
        p.skipWs();
        if (p.pos != p.src.length()) throw new RuntimeException("trailing garbage in JSON");
        return root;
    }

    // ------------------------------------------------------------------
    // Tree → ANF
    // ------------------------------------------------------------------

    private static AnfProgram toProgram(Map<?, ?> obj) {
        // F-084 (CX-BUG-046): every required field is checked for presence
        // AND JSON type. A missing or non-array `properties` / `methods` /
        // `params` / `body` used to load as an EMPTY list and a missing name as
        // null — so a public method whose `body` was "not-an-array" loaded with
        // zero bindings, passed every check below (each walks the bindings and
        // finds nothing), and `--ir --hex` exited 0 with an EMPTY locking
        // script. Each diagnostic names the malformed field's path.
        String name = reqString(obj, "contractName", "");
        String parentClass = optParentClass(obj);
        List<AnfProperty> props = new ArrayList<>();
        List<?> pl = reqList(obj, "properties", "");
        for (int i = 0; i < pl.size(); i++) {
            String path = "properties[" + i + "]";
            props.add(toProperty(asObject(pl.get(i), path), path));
        }
        List<AnfMethod> methods = new ArrayList<>();
        List<?> ml = reqList(obj, "methods", "");
        for (int i = 0; i < ml.size(); i++) {
            String path = "methods[" + i + "]";
            methods.add(toMethod(asObject(ml.get(i), path), path));
        }
        // N-060 / N-065: no name the compiler mints (shared diagnostic, 7 tiers).
        checkReservedIrNames(props, methods);

        // N-071: --ir skips Validate.java, whose ends-with-assert rule is what
        // makes a public method's script a covenant. Stack lowering leaves the
        // method's last binding as the script result, so `"body": []`
        // compiled to an EMPTY (anyone-can-spend) script. Same rule and words
        // as Go's F-004 check; see endsWithTerminalAssert.
        for (AnfMethod m : methods) {
            if (m.isPublic() && !"constructor".equals(m.name()) && !endsWithTerminalAssert(m.body())) {
                throw new RuntimeException(
                    "IR validation: public method '" + m.name() + "' must end with an assert() call"
                    + " (or an if/else whose arms both do, or a terminal raw_script with out_arity 1);"
                    + " otherwise the value its last binding leaves on the stack decides the spend"
                );
            }
        }

        // N-113 / R-081: a contract with no public method has no spending
        // entry point and emits an EMPTY locking script — which is
        // anyone-can-spend, not merely useless. On the real @bsv/sdk `Spend`
        // engine under full consensus rules, an empty locking script with the
        // one-byte push-only witness OP_1 (0x51) validates. Before this guard
        // the --ir path exited 0 and handed the SDKs a well-formed artifact
        // whose "script" was "".
        //
        // The source pipeline already rejects the same shape in Validate.java;
        // this loader is reached only from the --ir path, so this closes the
        // rule's gap on externally supplied IR.
        //
        // Checked LAST so the structural diagnostics from toMethod above keep
        // priority — a malformed binding is the more actionable error when
        // both are present. Mirrors compilers/go/ir/loader.go, ordering
        // included.
        //
        // N-113: the CONSTRUCTOR does not count. This mirrors Validate.java,
        // but runs over a differently-shaped list: the AST keeps the
        // constructor in its own field while ANF lowering flattens it INTO
        // `methods`, so one `isPublic: true` on the constructor walked past
        // the guard. It is never a spending entry point (Emit.java and
        // StackLower both filter it out by NAME) and the contract emitted an
        // EMPTY locking script at exit 0.
        boolean hasPublic = false;
        for (AnfMethod m : methods) {
            if (m.isPublic() && !"constructor".equals(m.name())) { hasPublic = true; break; }
        }
        if (!hasPublic) {
            throw new RuntimeException(
                "contract " + name + " has no public methods — no spending entry points;"
                + " an empty locking script is anyone-can-spend"
            );
        }

        // R-128 / R-165 family: builtin call arity. The source pipeline
        // type-checks every call; this loader is the `--ir` path, which runs no
        // frontend, so a wrong-arity call used to reach stack lowering — where
        // each dispatch family consumes args.size() from the stack MODEL and
        // then emits a FIXED-arity opcode blob. `cat` with one argument
        // compiled to a bare OP_CAT; `assert` with none compiled to an EMPTY
        // script, dropping the contract's only guard.
        for (AnfMethod m : methods) {
            String err = checkCallArity(m.body(), m.name());
            if (err != null) {
                throw new RuntimeException(err);
            }
        }
        // R-126 / CL-BUG-164: an add_output must name exactly one state value
        // per MUTABLE property.
        //
        // The source pipeline counts addOutput arity in the typechecker (the
        // N20 / N23 / N26 negatives). This loader is the `--ir` path, which
        // runs no frontend, so such a node reached stack lowering directly —
        // where lowerAddOutput serializes the OP_RETURN payload with the MIN of
        // the two lists. Under-arity emitted an output carrying fewer state
        // fields than the contract has; over-arity silently dropped the
        // surplus. Measured through each tier's own --ir CLI on a
        // two-mutable-field contract (correct arity = 1394 hexchars): go, rust,
        // zig, ruby, python and java ALL accepted, emitting 1388 and 1396
        // hexchars respectively.
        //
        // CL-BUG-164 settled the cost: every SDK's StateSerializer writes ALL
        // mutable fields, so a short-payload continuation is spendable only by
        // a hand-crafted transaction, and the successor it produces is
        // permanently unspendable because the next call's deserialize_state
        // slices at fixed offsets. The message is shared verbatim with the
        // other six tiers.
        int mutableCount = 0;
        for (AnfProperty p : props) {
            if (!p.readonly()) mutableCount++;
        }
        for (AnfMethod m : methods) {
            String err = checkAddOutputArity(m.body(), m.name(), mutableCount);
            if (err == null && !"constructor".equals(m.name())) {
                err = checkNoSuperCall(m.body(), m.name());
            }
            if (err != null) {
                throw new RuntimeException(err);
            }
        }
        return new AnfProgram(name, props, methods, parentClass);
    }

    /**
     * N-060 / N-065 — {@code --ir} names that alias a name the compiler mints.
     * Mirrors {@code assertNoReservedIrNames} in
     * packages/runar-compiler/src/index.ts: property, method and parameter
     * names, loop iterVars and the name a load_param / load_prop / update_prop
     * addresses are declarations (stack-lowering families plus the ANF binding
     * families {@code t<digits>} / {@code __merge$<digits>}); binding names and
     * every binding reference, {@code @ref:} aliases included, refuse the
     * stack-lowering families only. See {@link ReservedNames}.
     */
    private static void checkReservedIrNames(List<AnfProperty> props, List<AnfMethod> methods) {
        for (AnfProperty p : props) reservedIr(p.name(), true);
        for (AnfMethod m : methods) {
            reservedIr(m.name(), true);
            for (AnfParam p : m.params()) reservedIr(p.name(), true);
            reservedIrBody(m.body());
        }
    }

    private static void reservedIrBody(List<AnfBinding> bindings) {
        if (bindings == null) return;
        for (AnfBinding b : bindings) {
            reservedIr(b.name(), false);
            AnfValue v = b.value();
            if (v instanceof LoadParam lp) {
                reservedIr(lp.name(), true);
            } else if (v instanceof LoadProp lp) {
                reservedIr(lp.name(), true);
            } else if (v instanceof UpdateProp up) {
                reservedIr(up.name(), true);
                reservedIr(up.value(), false);
            } else if (v instanceof LoadConst lc) {
                if (lc.value() instanceof BytesConst bc && bc.hex() != null && bc.hex().startsWith("@ref:")) {
                    reservedIr(bc.hex().substring(5), false);
                }
            } else if (v instanceof Loop lo) {
                reservedIr(lo.iterVar(), true);
                reservedIrBody(lo.body());
            } else if (v instanceof If i) {
                reservedIr(i.cond(), false);
                reservedIrBody(i.thenBranch());
                reservedIrBody(i.elseBranch());
            } else if (v instanceof BinOp bo) {
                reservedIr(bo.left(), false);
                reservedIr(bo.right(), false);
            } else if (v instanceof UnaryOp uo) {
                reservedIr(uo.operand(), false);
            } else if (v instanceof Assert a) {
                reservedIr(a.value(), false);
            } else if (v instanceof Call c) {
                reservedIrAll(c.args());
            } else if (v instanceof MethodCall mc) {
                reservedIr(mc.object(), false);
                reservedIrAll(mc.args());
            } else if (v instanceof CheckPreimage cp) {
                reservedIr(cp.preimage(), false);
            } else if (v instanceof DeserializeState ds) {
                reservedIr(ds.preimage(), false);
            } else if (v instanceof AddOutput ao) {
                reservedIr(ao.satoshis(), false);
                reservedIrAll(ao.stateValues());
                reservedIr(ao.preimage(), false);
            } else if (v instanceof AddRawOutput ar) {
                reservedIr(ar.satoshis(), false);
                reservedIr(ar.scriptBytes(), false);
            } else if (v instanceof AddDataOutput ad) {
                reservedIr(ad.satoshis(), false);
                reservedIr(ad.scriptBytes(), false);
            } else if (v instanceof ArrayLiteral al) {
                reservedIrAll(al.elements());
            }
        }
    }

    private static void reservedIrAll(List<String> names) {
        if (names == null) return;
        for (String n : names) reservedIr(n, false);
    }

    private static void reservedIr(String name, boolean declaration) {
        if (name != null && ReservedNames.isReservedIrName(name, declaration)) {
            throw new RuntimeException(ReservedNames.message(name));
        }
    }

    /**
     * N-071: ANF form of the source validator's ends-with-assert rule — the
     * last binding is an {@code assert}, or an {@code if} whose then AND else
     * arms both end that way. A terminal {@code raw_script} with out_arity 1
     * (UnsafeSmartContract's {@code asm()} terminal) is also accepted, because
     * ANF carries no parentClass.
     */
    private static boolean endsWithTerminalAssert(List<AnfBinding> bindings) {
        if (bindings == null || bindings.isEmpty()) {
            return false;
        }
        AnfValue v = bindings.get(bindings.size() - 1).value();
        if (v instanceof runar.compiler.ir.anf.Assert) {
            return true;
        }
        if (v instanceof runar.compiler.ir.anf.If branch) {
            return endsWithTerminalAssert(branch.thenBranch()) && endsWithTerminalAssert(branch.elseBranch());
        }
        if (v instanceof runar.compiler.ir.anf.RawScript rs) {
            return rs.outArity() == 1;
        }
        return false;
    }

    /**
     * Walk a binding list — nested {@code if} arms and {@code loop} bodies
     * included — and report the first {@code add_output} whose stateValues list
     * is not exactly {@code mutableCount} long. See the call site in
     * {@code toProgram} for why.
     */
    private static String checkAddOutputArity(
        List<AnfBinding> bindings, String methodName, int mutableCount) {
        if (bindings == null) {
            return null;
        }
        for (AnfBinding b : bindings) {
            AnfValue v = b.value();
            if (v instanceof runar.compiler.ir.anf.AddOutput ao) {
                int got = ao.stateValues() == null ? 0 : ao.stateValues().size();
                if (got != mutableCount) {
                    return "add_output in method '" + methodName + "' carries " + got
                        + " state values, but the contract declares " + mutableCount
                        + " mutable properties. The output's OP_RETURN payload is serialized"
                        + " from this list while deserialize_state slices the declared"
                        + " properties at fixed offsets, so any other count commits to a state"
                        + " payload no SDK-built transaction can produce and a successor that"
                        + " cannot be spent.";
                }
            } else if (v instanceof runar.compiler.ir.anf.If branch) {
                String err = checkAddOutputArity(branch.thenBranch(), methodName, mutableCount);
                if (err == null) {
                    err = checkAddOutputArity(branch.elseBranch(), methodName, mutableCount);
                }
                if (err != null) {
                    return err;
                }
            } else if (v instanceof runar.compiler.ir.anf.Loop loop) {
                String err = checkAddOutputArity(loop.body(), methodName, mutableCount);
                if (err != null) {
                    return err;
                }
            }
        }
        return null;
    }

    /**
     * Refuse a {@code super} call anywhere in a non-constructor method body
     * (R-164).
     *
     * <p>{@code super} emits no opcodes — the constructor args are already on
     * the stack — but stack lowering pushes a model slot for it anyway: +1
     * model, +0 physical. On the source path that is invisible because the
     * constructor is never lowered to script; via {@code --ir} it is reachable,
     * and every subsequent PICK/ROLL depth in the method is off by one.
     * Measured against the same IR with the binding deleted: PUSH 3; OP_ROLL
     * where the correct lowering emits OP_ROT, addressing a fourth stack item
     * that does not exist.
     */
    private static String checkNoSuperCall(List<AnfBinding> bindings, String methodName) {
        if (bindings == null) {
            return null;
        }
        for (AnfBinding b : bindings) {
            AnfValue v = b.value();
            if (v instanceof runar.compiler.ir.anf.Call call && "super".equals(call.func())) {
                return "super() is only valid in a constructor; method '" + methodName
                    + "' calls it. It emits no opcodes — the constructor args are already on the"
                    + " stack — so stack lowering pushes a model slot with no physical value, and"
                    + " every later PICK/ROLL depth in the method is off by one.";
            }
            if (v instanceof runar.compiler.ir.anf.If branch) {
                String err = checkNoSuperCall(branch.thenBranch(), methodName);
                if (err == null) {
                    err = checkNoSuperCall(branch.elseBranch(), methodName);
                }
                if (err != null) {
                    return err;
                }
            } else if (v instanceof runar.compiler.ir.anf.Loop loop) {
                String err = checkNoSuperCall(loop.body(), methodName);
                if (err != null) {
                    return err;
                }
            }
        }
        return null;
    }

    private static AnfProperty toProperty(Map<?, ?> obj, String path) {
        String name = reqString(obj, "name", path);
        String type = reqString(obj, "type", path);
        boolean readonly = reqBool(obj, "readonly", path);
        ConstValue initial = null;
        Object iv = obj.get("initialValue");
        if (iv != null) initial = toConst(iv);
        return new AnfProperty(name, type, readonly, initial, toSyntheticChain(obj.get("syntheticArrayChain")));
    }

    /**
     * N-095: recover the expand-fixed-arrays chain. Absent (the normal case)
     * yields null, which {@code Jcs} omits again on re-emit, so
     * {@code --emit-ir → --ir → --emit-ir} is a fixed point.
     */
    private static List<AnfProperty.SyntheticArrayLevel> toSyntheticChain(Object raw) {
        if (raw == null) return null;
        if (!(raw instanceof List<?> lst)) {
            throw new RuntimeException("syntheticArrayChain is not an array");
        }
        List<AnfProperty.SyntheticArrayLevel> out = new ArrayList<>(lst.size());
        for (Object o : lst) {
            Map<?, ?> level = asObject(o);
            out.add(new AnfProperty.SyntheticArrayLevel(
                asString(level.get("base")),
                asInt(level.get("index"), "syntheticArrayChain.index"),
                asInt(level.get("length"), "syntheticArrayChain.length")));
        }
        return out;
    }

    /**
     * R-086: decode an integer-typed ANF field, REFUSING anything the field
     * cannot represent instead of keeping its low 32 bits.
     *
     * <p>{@code Long.intValue()} / {@code BigInteger.intValue()} truncate
     * silently, and this runs on the {@code --ir} path — externally supplied
     * IR. A {@code loop} count of 2^32+5 used to compile to exactly the bytes
     * count=5 compiles to, and a {@code loop} step of 2^32+1 used to compile to
     * a DIFFERENT locking script than the Go tier emitted from the same input
     * bytes. Both tiers accepted; only the scripts disagreed.
     *
     * <p>{@code Double} is refused outright: a JSON float is not an integer
     * (Go's {@code encoding/json} refuses it too), and {@code Number.intValue()}
     * would have clamped it.
     */
    private static int asInt(Object v, String what) {
        BigInteger b;
        if (v instanceof Long l) {
            b = BigInteger.valueOf(l);
        } else if (v instanceof Integer i) {
            b = BigInteger.valueOf(i);
        } else if (v instanceof BigInteger bi) {
            b = bi;
        } else {
            throw new RuntimeException(what + " is not an integer: "
                + (v == null ? "null" : v.getClass().getSimpleName()));
        }
        if (b.bitLength() > 31) {
            throw new RuntimeException(what + " is out of 32-bit signed range: " + b);
        }
        return b.intValue();
    }

    /**
     * N-115 — the unroll ceiling, at the external-input trust boundary.
     *
     * <p>{@link Loop#MAX_LOOP_COUNT} (10000) has existed in this tier all
     * along, but the only thing that read it was {@code AnfLower} — so it
     * bounded a loop written in SOURCE and not one arriving as IR.
     * {@code asInt} keeps the count inside 32-bit signed range (R-086), which
     * is a different and much weaker claim: 10001 is a perfectly good
     * {@code int}. This tier accepted it and emitted a 199734-hexchar (~97 KB)
     * locking script.
     *
     * <p>Cross-tier hex parity could not have caught it. Rust, Zig and Java all
     * accepted the same over-cap IR and all three emitted the SAME bytes
     * (sha256 {@code e2c1be39...}); only Go, Python and Ruby refused. Three
     * agreeing tiers look exactly like three correct ones to a comparison that
     * only diffs output.
     *
     * <p>The sentence is Go's, word for word ({@code compilers/go/ir/loader.go}),
     * minus the method / binding names this loader does not have in scope here.
     */
    private static int loopCount(Object v) {
        int count = asInt(v, "loop count");
        // N-117 — the OTHER half of the same bound. `asInt` only rejects a
        // count whose bitLength exceeds 31, which -3 passes cleanly, and the
        // ceiling check below is a `>` so it never looks downward. StackLower's
        // `for (int i = 0; i < count; i++)` then runs zero iterations and the
        // loop body is silently DELETED from the emitted script — this tier
        // answered 00009c77 (OP_0 OP_0 OP_NUMEQUAL OP_NIP) for IR whose other
        // six tiers all refuse it, comparing a constant 0 against a constructor
        // slot: anyone-can-spend when that slot is 0, unspendable otherwise.
        //
        // Go (`compilers/go/ir/loader.go`) checks both bounds and its sentence
        // is reused here, minus the method / binding names this loader does not
        // have in scope.
        if (count < 0) {
            throw new RuntimeException("has negative loop count " + count);
        }
        if (count > Loop.MAX_LOOP_COUNT) {
            throw new RuntimeException(
                "has loop count " + count + " exceeding maximum " + Loop.MAX_LOOP_COUNT
            );
        }
        return count;
    }

    private static AnfMethod toMethod(Map<?, ?> obj, String path) {
        String name = reqString(obj, "name", path);
        boolean isPublic = reqBool(obj, "isPublic", path);
        Integer sigHashType = optSigHashType(obj, path);
        List<AnfParam> params = new ArrayList<>();
        List<?> pl = reqList(obj, "params", path);
        for (int i = 0; i < pl.size(); i++) {
            String pp = path + ".params[" + i + "]";
            Map<?, ?> po = asObject(pl.get(i), pp);
            params.add(new AnfParam(reqString(po, "name", pp), reqString(po, "type", pp)));
        }
        List<AnfBinding> body = toBindingList(obj, "body", path);
        return new AnfMethod(name, params, body, isPublic, sigHashType);
    }

    /** Walks every binding, including nested ones, checking builtin arity. */
    private static String checkCallArity(List<AnfBinding> bindings, String methodName) {
        if (bindings == null) {
            return null;
        }
        for (AnfBinding b : bindings) {
            AnfValue v = b.value();
            if (v instanceof runar.compiler.ir.anf.Call call) {
                String err = BuiltinArity.check(
                    methodName, b.name(), call.func(),
                    call.args() == null ? 0 : call.args().size());
                if (err != null) {
                    return err;
                }
            } else if (v instanceof runar.compiler.ir.anf.If branch) {
                String err = checkCallArity(branch.thenBranch(), methodName);
                if (err == null) {
                    err = checkCallArity(branch.elseBranch(), methodName);
                }
                if (err != null) {
                    return err;
                }
            } else if (v instanceof runar.compiler.ir.anf.Loop loop) {
                String err = checkCallArity(loop.body(), methodName);
                if (err != null) {
                    return err;
                }
            }
        }
        return null;
    }

    private static AnfBinding toBinding(Map<?, ?> obj, String path) {
        String name = reqString(obj, "name", path);
        AnfValue v = toValue(asObject(obj.get("value"), path + ".value"), path + ".value");
        // GAP-002: round-trip the optional `sourceLoc` field. Used for
        // source-map plumbing; omitted (null) for legacy / hand-written
        // ANF inputs.
        runar.compiler.ir.ast.SourceLocation loc = null;
        Object locRaw = obj.get("sourceLoc");
        if (locRaw instanceof Map<?, ?> locObj) {
            String file = asString(locObj.get("file"));
            int line = asInt(locObj.get("line"), "sourceLoc line");
            int col = asInt(locObj.get("column"), "sourceLoc column");
            loc = new runar.compiler.ir.ast.SourceLocation(file, line, col);
        }
        return new AnfBinding(name, v, loc);
    }


    private static AnfValue toValue(Map<?, ?> obj, String path) {
        String kind = reqString(obj, "kind", path);
        return switch (kind) {
            case "load_param" -> new LoadParam(reqString(obj, "name", path));
            case "load_prop" -> new LoadProp(reqString(obj, "name", path));
            case "load_const" -> new LoadConst(toConst(obj.get("value")));
            case "bin_op" -> new BinOp(
                reqString(obj, "op", path),
                reqString(obj, "left", path),
                reqString(obj, "right", path),
                asOptString(obj.get("result_type"))
            );
            case "unary_op" -> new UnaryOp(
                reqString(obj, "op", path),
                reqString(obj, "operand", path),
                asOptString(obj.get("result_type"))
            );
            case "call" -> new Call(reqString(obj, "func", path), toStringList(obj, "args", path));
            case "method_call" -> new MethodCall(
                reqString(obj, "object", path),
                reqString(obj, "method", path),
                toStringList(obj, "args", path)
            );
            case "if" -> new If(
                reqString(obj, "cond", path),
                toBindingList(obj, "then", path),
                toBindingList(obj, "else", path),
                obj.containsKey("results") ? toStringList(obj, "results", path) : null
            );
            case "loop" -> new Loop(
                loopCount(obj.get("count")),
                toBindingList(obj, "body", path),
                reqString(obj, "iterVar", path),
                // Iterator start / step (issue #121). Older payloads without
                // these describe zero-start counting-up loops.
                obj.containsKey("start") ? loopStart(obj.get("start")) : BigInteger.ZERO,
                obj.containsKey("step") ? asInt(obj.get("step"), "loop step") : 1
            );
            case "assert" -> new Assert(
                reqString(obj, "value", path),
                obj.containsKey("isAutoInjectedStateCheck")
                    && Boolean.TRUE.equals(obj.get("isAutoInjectedStateCheck"))
            );
            case "update_prop" -> new UpdateProp(reqString(obj, "name", path), reqString(obj, "value", path));
            case "get_state_script" -> new GetStateScript();
            case "check_preimage" -> new CheckPreimage(
                reqString(obj, "preimage", path),
                obj.containsKey("sighashFlag") && obj.get("sighashFlag") != null
                    ? asInt(obj.get("sighashFlag"), "check_preimage sighashFlag") : null
            );
            case "deserialize_state" -> new DeserializeState(reqString(obj, "preimage", path));
            case "add_output" -> {
                String sat = reqString(obj, "satoshis", path);
                List<String> sv = toStringList(obj, "stateValues", path);
                String preimage = obj.containsKey("preimage") ? asString(obj.get("preimage")) : "";
                yield new AddOutput(sat, sv, preimage == null ? "" : preimage);
            }
            case "add_raw_output" -> new AddRawOutput(
                reqString(obj, "satoshis", path),
                reqString(obj, "scriptBytes", path)
            );
            case "add_data_output" -> new AddDataOutput(
                reqString(obj, "satoshis", path),
                reqString(obj, "scriptBytes", path)
            );
            case "array_literal" -> new ArrayLiteral(toStringList(obj, "elements", path));
            case "raw_script" -> toRawScript(obj);
            default -> throw new UnknownAnfKindError(kind, "anf-loader.parseValue");
        };
    }

    /**
     * Decode a raw_script ANF value. Validates the hex body shape (even
     * length, hex chars) and non-negative arities up front so malformed IR
     * fails fast at load time rather than at lowering time.
     */
    private static RawScript toRawScript(Map<?, ?> obj) {
        String bytes = asString(obj.get("bytes"));
        if (bytes == null) bytes = "";
        // N-113 / R-079: an empty span is a claim the emitter cannot honour.
        // Stack lowering models a raw_script purely from its declared arities
        // (it pops in_arity and pushes out_arity) because the bytes are opaque
        // to it, while emission writes nothing at all for a zero-length span.
        // The stack model and the script then disagree, and every later
        // PICK/ROLL depth derived from that model addresses the wrong slot —
        // the span silently degrades to the identity function and a different
        // witness spends the output than the IR declared.
        //
        // The source path already rejects this ("asm() body must be a
        // non-empty hex string literal", Validate.java); --ir is the same rule
        // at the external-input trust boundary. All empty bodies are rejected,
        // including the degenerate in=0/out=0 case, because mirroring the
        // source validator exactly is worth more than an arity-conditional
        // rule that would differ from the rule one pass earlier.
        if (bytes.isEmpty()) {
            throw new RuntimeException(
                "raw_script has an empty bytes body but declares in_arity "
                + asInt(obj.get("in_arity"), "raw_script in_arity") + " / out_arity "
                + asInt(obj.get("out_arity"), "raw_script out_arity")
                + "; a span that emits no bytes cannot have a stack effect"
            );
        }
        if ((bytes.length() & 1) != 0) {
            throw new RuntimeException(
                "raw_script bytes have odd hex length " + bytes.length()
            );
        }
        if (!isHexString(bytes)) {
            throw new RuntimeException(
                "raw_script bytes contain non-hex characters"
            );
        }
        int inArity = asInt(obj.get("in_arity"), "raw_script in_arity");
        int outArity = asInt(obj.get("out_arity"), "raw_script out_arity");
        if (inArity < 0) {
            throw new RuntimeException(
                "raw_script has negative in_arity " + inArity
            );
        }
        if (outArity < 0) {
            throw new RuntimeException(
                "raw_script has negative out_arity " + outArity
            );
        }
        return new RawScript(bytes, inArity, outArity);
    }

    private static boolean isHexString(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9')
                || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    private static ConstValue toConst(Object v) {
        if (v instanceof Boolean b) return new BoolConst(b);
        if (v instanceof BigInteger bi) return new BigIntConst(bi);
        if (v instanceof Long l) return new BigIntConst(BigInteger.valueOf(l));
        if (v instanceof Integer i) return new BigIntConst(BigInteger.valueOf(i));
        if (v instanceof String s) {
            // A JSON string in the load_const value position is either:
            //   1. A decimal-encoded BigInt with the canonical JS BigInt
            //      `n` suffix (e.g. "115792...41n") — the only way to
            //      round-trip oversize 256-bit constants through JSON
            //      without losing precision.
            //   2. A hex-encoded ByteString literal (never carries the
            //      `n` suffix; an `n` would not be a hex character).
            // The trailing `n` is the discriminator — matches the rule
            // in compilers/go/ir/types.go::isDecimalBigIntLiteral and
            // packages/runar-compiler/src/__tests__/cross-compiler.test.ts.
            if (isDecimalBigIntLiteral(s)) {
                String body = s.substring(0, s.length() - 1);
                return new BigIntConst(new BigInteger(body, 10));
            }
            return new BytesConst(s);
        }
        throw new RuntimeException("unexpected const type: " + (v == null ? "null" : v.getClass()));
    }

    /**
     * Returns whether {@code s} is a JS-style decimal BigInt literal:
     * optional leading {@code -}, one or more ASCII digits, REQUIRED
     * trailing {@code n} marker. Mirrors Go's
     * {@code isDecimalBigIntLiteral} so the IR round-trips losslessly
     * across tiers. Without the {@code n} discriminator a hex string
     * like {@code "3030"} would be ambiguously decodable as either the
     * integer 3030 or the 2-byte bytestring {@code 0x30 0x30}.
     */
    static boolean isDecimalBigIntLiteral(String s) {
        if (s == null || s.length() < 2) return false;
        if (s.charAt(s.length() - 1) != 'n') return false;
        int start = 0;
        if (s.charAt(0) == '-') start = 1;
        int body = s.length() - 1;
        if (body - start < 1) return false;
        for (int i = start; i < body; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    /** Required binding array {@code obj[key]}; each element decoded at its own path. */
    private static List<AnfBinding> toBindingList(Map<?, ?> obj, String key, String path) {
        String lp = fieldPath(path, key);
        List<?> lst = reqList(obj, key, path);
        List<AnfBinding> out = new ArrayList<>(lst.size());
        for (int i = 0; i < lst.size(); i++) {
            String bp = lp + "[" + i + "]";
            out.add(toBinding(asObject(lst.get(i), bp), bp));
        }
        return out;
    }

    /** Required array of strings {@code obj[key]}; a null element is refused. */
    private static List<String> toStringList(Map<?, ?> obj, String key, String path) {
        String lp = fieldPath(path, key);
        List<?> lst = reqList(obj, key, path);
        List<String> out = new ArrayList<>(lst.size());
        for (int i = 0; i < lst.size(); i++) {
            Object e = lst.get(i);
            if (!(e instanceof String str)) {
                throw malformed(lp + "[" + i + "]", "a string", e);
            }
            out.add(str);
        }
        return out;
    }

    private static String fieldPath(String path, String key) {
        return path.isEmpty() ? key : path + "." + key;
    }

    /**
     * F-038 / F-065: the two OPTIONAL keys the artifact copies into the fields
     * the SDK signs by. Absent (or JSON null) is legal — IR written before they
     * existed — but a present value must be one the source path can produce:
     * an unknown parentClass or a FORKID-less sigHashType would otherwise reach
     * the artifact and steer the SDK into a spend the script rejects. Same
     * words as {@code packages/runar-compiler/src/ir/anf-required-fields.ts}.
     */
    private static final List<String> PARENT_CLASSES =
        List.of("SmartContract", "StatefulSmartContract", "UnsafeSmartContract");
    private static final List<Long> SIGHASH_TYPES = List.of(0x41L, 0x42L, 0x43L, 0xc1L, 0xc2L, 0xc3L);

    private static String optParentClass(Map<?, ?> obj) {
        Object v = obj.get("parentClass");
        if (v == null) return null;
        if (!(v instanceof String s)) throw malformed("parentClass", "a string", v);
        if (!PARENT_CLASSES.contains(s)) {
            throw new RuntimeException("IR validation: parentClass must be one of "
                + String.join(", ", PARENT_CLASSES) + ", got " + s);
        }
        return s;
    }

    private static Integer optSigHashType(Map<?, ?> obj, String path) {
        Object v = obj.get("sigHashType");
        if (v == null) return null;
        String lp = fieldPath(path, "sigHashType");
        if (v instanceof String || v instanceof Boolean || v instanceof List<?> || v instanceof Map<?, ?>) {
            throw malformed(lp, "an integer", v);
        }
        Long value = null;
        if (v instanceof Long l) value = l;
        else if (v instanceof Integer i) value = i.longValue();
        else if (v instanceof BigInteger bi && bi.bitLength() < 63) value = bi.longValue();
        if (value == null || !SIGHASH_TYPES.contains(value)) {
            StringBuilder allowed = new StringBuilder();
            for (Long t : SIGHASH_TYPES) {
                if (allowed.length() > 0) allowed.append(", ");
                allowed.append(t);
            }
            throw new RuntimeException("IR validation: " + lp + " must be one of " + allowed + ", got " + v);
        }
        return value.intValue();
    }

    private static String jsonType(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return "string";
        if (v instanceof Boolean) return "boolean";
        if (v instanceof List<?>) return "array";
        if (v instanceof Map<?, ?>) return "object";
        return "number";
    }

    private static RuntimeException malformed(String fieldPath, String expected, Object got) {
        return new RuntimeException(
            "IR validation: " + fieldPath + " must be " + expected + ", got " + jsonType(got));
    }

    /** Present-and-typed accessors: absence and a JSON null are both refused. */
    private static Object req(Map<?, ?> obj, String key, String path) {
        if (!obj.containsKey(key) || obj.get(key) == null) {
            throw new RuntimeException(
                "IR validation: required field " + fieldPath(path, key) + " is missing");
        }
        return obj.get(key);
    }

    private static String reqString(Map<?, ?> obj, String key, String path) {
        Object v = req(obj, key, path);
        if (v instanceof String s) return s;
        throw malformed(fieldPath(path, key), "a string", v);
    }

    private static List<?> reqList(Map<?, ?> obj, String key, String path) {
        Object v = req(obj, key, path);
        if (v instanceof List<?> l) return l;
        throw malformed(fieldPath(path, key), "an array", v);
    }

    private static boolean reqBool(Map<?, ?> obj, String key, String path) {
        Object v = req(obj, key, path);
        if (v instanceof Boolean b) return b;
        throw malformed(fieldPath(path, key), "a boolean", v);
    }

    private static Map<?, ?> asObject(Object v, String path) {
        if (v instanceof Map<?, ?> m) return m;
        throw malformed(path, "an object", v);
    }

    private static Map<?, ?> asObject(Object v) {
        if (v instanceof Map<?, ?> m) return m;
        throw new RuntimeException("expected object, got " + (v == null ? "null" : v.getClass()));
    }

    private static String asString(Object v) {
        if (v instanceof String s) return s;
        if (v == null) return null;
        throw new RuntimeException("expected string, got " + v.getClass());
    }

    private static String asOptString(Object v) {
        if (v == null) return null;
        return asString(v);
    }

    private static BigInteger asBigInt(Object v) {
        if (v instanceof BigInteger bi) return bi;
        if (v instanceof Long l) return BigInteger.valueOf(l);
        if (v instanceof Integer i) return BigInteger.valueOf(i);
        throw new RuntimeException("expected integer, got " + (v == null ? "null" : v.getClass()));
    }

    /**
     * A {@code loop}'s iterator start: a JSON integer, or the sanctioned
     * {@code "<decimal>n"} string for a start too wide for a tier's native
     * integer (issue #121).
     *
     * <p>The schema has said {@code integer | string} all along, and the
     * {@code n}-suffixed decimal string is the same encoding
     * {@code load_const.value} and {@code ANFProperty.initialValue} already
     * use — both of which this loader already accepts as strings.
     * {@code loop.start} was the one place the arm was missing, so this tier
     * refused ({@code exit 65}, "expected integer, got class
     * java.lang.String") a payload its five peers accepted and agreed on
     * byte-for-byte.
     *
     * <p>The suffix is REQUIRED, and that narrowness is the point. The peers
     * agree on {@code "0n"} / {@code "5n"} / {@code "-3n"} and on nothing
     * else: {@code "5"} reads as 5 in go/python/zig/ruby and as 0 in rust;
     * {@code "abc"}, {@code ""} and {@code "5nn"} are refused by go and python
     * and read as 0 by rust/zig/ruby. There is no majority answer to adopt for
     * any of those, so they keep the existing refusal. Refusing an input the
     * tiers disagree about is the safe side of that line — the alternative is
     * silently inventing a loop start, which is the class of defect N-131 was
     * about.
     *
     * <p>Strips exactly ONE trailing {@code n} and then requires the remainder
     * to be a plain decimal, so {@code "5nn"} and {@code "n"} stay refused and
     * a float-shaped {@code "1.5n"} cannot sneak a float back in through the
     * string arm.
     */
    private static BigInteger loopStart(Object v) {
        if (v instanceof String s) {
            if (s.length() >= 2 && s.charAt(s.length() - 1) == 'n') {
                String decimal = s.substring(0, s.length() - 1);
                try {
                    return new BigInteger(decimal);
                } catch (NumberFormatException e) {
                    throw new RuntimeException(
                        "loop start: expected a decimal integer before the `n` suffix, got \"" + s + "\"");
                }
            }
            throw new RuntimeException(
                "loop start: a string start must be the `<decimal>n` form, got \"" + s + "\"");
        }
        if (v instanceof BigInteger bi) return bi;
        if (v instanceof Long l) return BigInteger.valueOf(l);
        if (v instanceof Integer i) return BigInteger.valueOf(i);
        throw new RuntimeException(
            "loop start: expected an integer or a `<decimal>n` string, got "
                + (v == null ? "null" : v.getClass()));
    }

    // ------------------------------------------------------------------
    // Minimal JSON parser (object/array/string/number/bool/null)
    // ------------------------------------------------------------------

    private static final class JsonParser {
        final String src;
        int pos;

        JsonParser(String src) { this.src = src; }

        Object parseValue() {
            skipWs();
            if (pos >= src.length()) throw new RuntimeException("unexpected end of input");
            char c = src.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't', 'f' -> parseBool();
                case 'n' -> parseNull();
                default -> parseNumber();
            };
        }

        Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> out = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { pos++; return out; }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                expect(':');
                Object val = parseValue();
                out.put(key, val);
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; return out; }
                throw new RuntimeException("expected ',' or '}' at pos " + pos);
            }
        }

        List<Object> parseArray() {
            expect('[');
            List<Object> out = new ArrayList<>();
            skipWs();
            if (peek() == ']') { pos++; return out; }
            while (true) {
                out.add(parseValue());
                skipWs();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; return out; }
                throw new RuntimeException("expected ',' or ']' at pos " + pos);
            }
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= src.length()) throw new RuntimeException("unterminated escape");
                    char e = src.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > src.length()) throw new RuntimeException("short \\u escape");
                            int cp = Integer.parseInt(src.substring(pos, pos + 4), 16);
                            sb.append((char) cp);
                            pos += 4;
                        }
                        default -> throw new RuntimeException("bad escape \\" + e);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new RuntimeException("unterminated string");
        }

        Boolean parseBool() {
            if (src.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
            if (src.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
            throw new RuntimeException("invalid literal at pos " + pos);
        }

        Object parseNull() {
            if (src.startsWith("null", pos)) { pos += 4; return null; }
            throw new RuntimeException("invalid literal at pos " + pos);
        }

        Object parseNumber() {
            int start = pos;
            if (pos < src.length() && (src.charAt(pos) == '-' || src.charAt(pos) == '+')) pos++;
            boolean isFloat = false;
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (Character.isDigit(c)) { pos++; continue; }
                if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { isFloat = true; pos++; continue; }
                break;
            }
            String s = src.substring(start, pos);
            if (isFloat) return Double.parseDouble(s);
            // Use BigInteger to preserve precision for large bigints.
            BigInteger bi = new BigInteger(s);
            if (bi.bitLength() < 63) return bi.longValueExact();
            return bi;
        }

        void skipWs() {
            while (pos < src.length()) {
                char c = src.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
                else break;
            }
        }

        void expect(char c) {
            skipWs();
            if (pos >= src.length() || src.charAt(pos) != c) {
                throw new RuntimeException("expected '" + c + "' at pos " + pos);
            }
            pos++;
        }

        char peek() {
            skipWs();
            if (pos >= src.length()) return '\0';
            return src.charAt(pos);
        }
    }
}
