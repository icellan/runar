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

    // ------------------------------------------------------------------
    // Tree → ANF
    // ------------------------------------------------------------------

    private static AnfProgram toProgram(Map<?, ?> obj) {
        String name = asString(obj.get("contractName"));
        List<AnfProperty> props = new ArrayList<>();
        Object pl = obj.get("properties");
        if (pl instanceof List<?> lst) {
            for (Object p : lst) props.add(toProperty(asObject(p)));
        }
        List<AnfMethod> methods = new ArrayList<>();
        Object ml = obj.get("methods");
        if (ml instanceof List<?> lst) {
            for (Object m : lst) methods.add(toMethod(asObject(m)));
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
        return new AnfProgram(name, props, methods);
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

    private static AnfProperty toProperty(Map<?, ?> obj) {
        String name = asString(obj.get("name"));
        String type = asString(obj.get("type"));
        boolean readonly = Boolean.TRUE.equals(obj.get("readonly"));
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

    private static AnfMethod toMethod(Map<?, ?> obj) {
        String name = asString(obj.get("name"));
        boolean isPublic = Boolean.TRUE.equals(obj.get("isPublic"));
        List<AnfParam> params = new ArrayList<>();
        Object pl = obj.get("params");
        if (pl instanceof List<?> lst) {
            for (Object p : lst) {
                Map<?, ?> po = asObject(p);
                params.add(new AnfParam(asString(po.get("name")), asString(po.get("type"))));
            }
        }
        List<AnfBinding> body = new ArrayList<>();
        Object bl = obj.get("body");
        if (bl instanceof List<?> lst) {
            for (Object b : lst) body.add(toBinding(asObject(b)));
        }
        return new AnfMethod(name, params, body, isPublic);
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

    private static AnfBinding toBinding(Map<?, ?> obj) {
        String name = asString(obj.get("name"));
        AnfValue v = toValue(asObject(obj.get("value")));
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


    private static AnfValue toValue(Map<?, ?> obj) {
        String kind = asString(obj.get("kind"));
        return switch (kind) {
            case "load_param" -> new LoadParam(asString(obj.get("name")));
            case "load_prop" -> new LoadProp(asString(obj.get("name")));
            case "load_const" -> new LoadConst(toConst(obj.get("value")));
            case "bin_op" -> new BinOp(
                asString(obj.get("op")),
                asString(obj.get("left")),
                asString(obj.get("right")),
                asOptString(obj.get("result_type"))
            );
            case "unary_op" -> new UnaryOp(
                asString(obj.get("op")),
                asString(obj.get("operand")),
                asOptString(obj.get("result_type"))
            );
            case "call" -> new Call(asString(obj.get("func")), toStringList(obj.get("args")));
            case "method_call" -> new MethodCall(
                asString(obj.get("object")),
                asString(obj.get("method")),
                toStringList(obj.get("args"))
            );
            case "if" -> new If(
                asString(obj.get("cond")),
                toBindingList(obj.get("then")),
                toBindingList(obj.get("else")),
                obj.containsKey("results") ? toStringList(obj.get("results")) : null
            );
            case "loop" -> new Loop(
                loopCount(obj.get("count")),
                toBindingList(obj.get("body")),
                asString(obj.get("iterVar")),
                // Iterator start / step (issue #121). Older payloads without
                // these describe zero-start counting-up loops.
                obj.containsKey("start") ? asBigInt(obj.get("start")) : BigInteger.ZERO,
                obj.containsKey("step") ? asInt(obj.get("step"), "loop step") : 1
            );
            case "assert" -> new Assert(
                asString(obj.get("value")),
                obj.containsKey("isAutoInjectedStateCheck")
                    && Boolean.TRUE.equals(obj.get("isAutoInjectedStateCheck"))
            );
            case "update_prop" -> new UpdateProp(asString(obj.get("name")), asString(obj.get("value")));
            case "get_state_script" -> new GetStateScript();
            case "check_preimage" -> new CheckPreimage(
                asString(obj.get("preimage")),
                obj.containsKey("sighashFlag") && obj.get("sighashFlag") != null
                    ? asInt(obj.get("sighashFlag"), "check_preimage sighashFlag") : null
            );
            case "deserialize_state" -> new DeserializeState(asString(obj.get("preimage")));
            case "add_output" -> {
                String sat = asString(obj.get("satoshis"));
                List<String> sv = toStringList(obj.get("stateValues"));
                String preimage = obj.containsKey("preimage") ? asString(obj.get("preimage")) : "";
                yield new AddOutput(sat, sv, preimage == null ? "" : preimage);
            }
            case "add_raw_output" -> new AddRawOutput(
                asString(obj.get("satoshis")),
                asString(obj.get("scriptBytes"))
            );
            case "add_data_output" -> new AddDataOutput(
                asString(obj.get("satoshis")),
                asString(obj.get("scriptBytes"))
            );
            case "array_literal" -> new ArrayLiteral(toStringList(obj.get("elements")));
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

    private static List<AnfBinding> toBindingList(Object v) {
        List<AnfBinding> out = new ArrayList<>();
        if (v instanceof List<?> lst) {
            for (Object b : lst) out.add(toBinding(asObject(b)));
        }
        return out;
    }

    private static List<String> toStringList(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof List<?> lst) {
            for (Object e : lst) out.add(asString(e));
        }
        return out;
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
