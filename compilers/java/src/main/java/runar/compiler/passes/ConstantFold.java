package runar.compiler.passes;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import runar.compiler.ir.anf.AnfBinding;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.anf.AnfValue;
import runar.compiler.ir.anf.BigIntConst;
import runar.compiler.ir.anf.BinOp;
import runar.compiler.ir.anf.BoolConst;
import runar.compiler.ir.anf.BytesConst;
import runar.compiler.ir.anf.Call;
import runar.compiler.ir.anf.ConstValue;
import runar.compiler.ir.anf.If;
import runar.compiler.ir.anf.LoadConst;
import runar.compiler.ir.anf.Loop;
import runar.compiler.ir.anf.UnaryOp;

/**
 * Constant folding pass for ANF IR (Pass 4.25).
 *
 * <p>Evaluates compile-time-known arithmetic, bitwise, comparison, and
 * boolean expressions and replaces the binding RHS with a {@code load_const}
 * literal.  Constants are propagated through the binding chain so downstream
 * operations can be folded too.
 *
 * <p>Direct port of {@code compilers/python/runar_compiler/frontend/constant_fold.py}
 * and {@code compilers/go/frontend/constant_fold.go}; consult those for the
 * authoritative semantics.  Side-effecting bindings (assert, update_prop,
 * check_preimage, deserialize_state, add_output, add_raw_output,
 * add_data_output, method_call, get_state_script) are passed through
 * untouched.  Only pure math builtins are folded across calls; cryptographic
 * builtins (hash160, checkSig, sha256*, ec*, slhDsa*, wots*, ...) are left
 * alone because their inputs may not be compile-time-known and folding would
 * be unsafe.
 *
 * <p>Gated by the CLI flag {@code --disable-constant-folding}; when set, the
 * pass is skipped entirely (matches the conformance-runner contract).
 */
public final class ConstantFold {

    private ConstantFold() {}

    /** Apply constant folding to an ANF program. Returns a new program; input is not mutated. */
    public static AnfProgram run(AnfProgram program) {
        List<AnfMethod> folded = new ArrayList<>(program.methods().size());
        for (AnfMethod m : program.methods()) {
            folded.add(foldMethod(m));
        }
        return new AnfProgram(program.contractName(), program.properties(), folded);
    }

    private static AnfMethod foldMethod(AnfMethod method) {
        Map<String, ConstSlot> env = new HashMap<>();
        List<AnfBinding> body = foldBindings(method.body(), env);
        return new AnfMethod(method.name(), method.params(), body, method.isPublic());
    }

    // ---------------------------------------------------------------
    // Constant environment
    // ---------------------------------------------------------------

    /** Tagged-union view of a folded constant; mirrors Python's ConstValue tuple. */
    private record ConstSlot(Kind kind, BigInteger bigInt, boolean boolVal, String strVal) {
        enum Kind { INT, BOOL, STR }

        static ConstSlot ofInt(BigInteger v) { return new ConstSlot(Kind.INT, v, false, null); }
        static ConstSlot ofBool(boolean v) { return new ConstSlot(Kind.BOOL, null, v, null); }
        static ConstSlot ofStr(String v) { return new ConstSlot(Kind.STR, null, false, v); }
    }

    // ---------------------------------------------------------------
    // Binding-level folding
    // ---------------------------------------------------------------

    private static List<AnfBinding> foldBindings(List<AnfBinding> bindings, Map<String, ConstSlot> env) {
        List<AnfBinding> out = new ArrayList<>(bindings.size());
        for (AnfBinding b : bindings) {
            out.add(foldBinding(b, env));
        }
        return out;
    }

    private static AnfBinding foldBinding(AnfBinding binding, Map<String, ConstSlot> env) {
        AnfValue folded = foldValue(binding.value(), env);
        ConstSlot slot = anfValueToConst(folded);
        if (slot != null) {
            env.put(binding.name(), slot);
        }
        return new AnfBinding(binding.name(), folded, binding.sourceLoc());
    }

    // ---------------------------------------------------------------
    // Value folding
    // ---------------------------------------------------------------

    private static AnfValue foldValue(AnfValue value, Map<String, ConstSlot> env) {
        // Pass-through for constants and loads
        if (value instanceof LoadConst || value.kind().equals("load_param") || value.kind().equals("load_prop")) {
            return value;
        }

        if (value instanceof BinOp bin) {
            ConstSlot left = env.get(bin.left());
            ConstSlot right = env.get(bin.right());
            if (left != null && right != null) {
                ConstSlot result = evalBinOp(bin.op(), left, right);
                if (result != null) {
                    return constToAnfValue(result);
                }
            }
            return value;
        }

        if (value instanceof UnaryOp un) {
            ConstSlot operand = env.get(un.operand());
            if (operand != null) {
                ConstSlot result = evalUnaryOp(un.op(), operand);
                if (result != null) {
                    return constToAnfValue(result);
                }
            }
            return value;
        }

        if (value instanceof Call call) {
            // Only fold when every arg is a known constant.
            List<String> args = call.args();
            if (args != null) {
                List<ConstSlot> constArgs = new ArrayList<>(args.size());
                boolean allConst = true;
                for (String a : args) {
                    ConstSlot s = env.get(a);
                    if (s == null) {
                        allConst = false;
                        break;
                    }
                    constArgs.add(s);
                }
                if (allConst) {
                    ConstSlot folded = evalBuiltinCall(call.func(), constArgs);
                    if (folded != null) {
                        return constToAnfValue(folded);
                    }
                }
            }
            return value;
        }

        if (value instanceof If ifv) {
            ConstSlot cond = env.get(ifv.cond());
            if (cond != null && cond.kind() == ConstSlot.Kind.BOOL) {
                if (cond.boolVal()) {
                    Map<String, ConstSlot> thenEnv = new HashMap<>(env);
                    List<AnfBinding> foldedThen = foldBindings(orEmpty(ifv.thenBranch()), thenEnv);
                    // Merge constants from the taken branch back into the outer env.
                    for (AnfBinding b : foldedThen) {
                        ConstSlot s = anfValueToConst(b.value());
                        if (s != null) env.put(b.name(), s);
                    }
                    return new If(ifv.cond(), foldedThen, List.of());
                }
                Map<String, ConstSlot> elseEnv = new HashMap<>(env);
                List<AnfBinding> foldedElse = foldBindings(orEmpty(ifv.elseBranch()), elseEnv);
                for (AnfBinding b : foldedElse) {
                    ConstSlot s = anfValueToConst(b.value());
                    if (s != null) env.put(b.name(), s);
                }
                return new If(ifv.cond(), List.of(), foldedElse);
            }
            // Condition not known — fold both branches independently.
            Map<String, ConstSlot> thenEnv = new HashMap<>(env);
            Map<String, ConstSlot> elseEnv = new HashMap<>(env);
            List<AnfBinding> foldedThen = foldBindings(orEmpty(ifv.thenBranch()), thenEnv);
            List<AnfBinding> foldedElse = foldBindings(orEmpty(ifv.elseBranch()), elseEnv);
            return new If(ifv.cond(), foldedThen, foldedElse);
        }

        if (value instanceof Loop lp) {
            Map<String, ConstSlot> bodyEnv = new HashMap<>(env);
            List<AnfBinding> foldedBody = foldBindings(orEmpty(lp.body()), bodyEnv);
            return new Loop(lp.count(), foldedBody, lp.iterVar());
        }

        // Side-effecting / opaque values pass through unchanged. This matches
        // the Python `_has_side_effect` set: assert, update_prop, check_preimage,
        // deserialize_state, add_output, add_raw_output, add_data_output,
        // method_call, get_state_script.
        return value;
    }

    private static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }

    // ---------------------------------------------------------------
    // ANF Value <-> ConstSlot conversion
    // ---------------------------------------------------------------

    private static ConstSlot anfValueToConst(AnfValue v) {
        if (!(v instanceof LoadConst lc)) return null;
        ConstValue cv = lc.value();
        if (cv instanceof BigIntConst bi) {
            return ConstSlot.ofInt(bi.value());
        }
        if (cv instanceof BoolConst bo) {
            return ConstSlot.ofBool(bo.value());
        }
        if (cv instanceof BytesConst bs) {
            String hex = bs.hex();
            // @ref: aliases are binding references (used by EC optimizer), not real constants.
            if (hex != null && hex.startsWith("@ref:")) return null;
            return ConstSlot.ofStr(hex);
        }
        return null;
    }

    private static AnfValue constToAnfValue(ConstSlot slot) {
        return switch (slot.kind()) {
            case INT -> new LoadConst(new BigIntConst(slot.bigInt()));
            case BOOL -> new LoadConst(new BoolConst(slot.boolVal()));
            case STR -> new LoadConst(new BytesConst(slot.strVal()));
        };
    }

    // ---------------------------------------------------------------
    // Binary operation evaluation
    // ---------------------------------------------------------------

    private static ConstSlot evalBinOp(String op, ConstSlot left, ConstSlot right) {
        // Arithmetic / bitwise / comparison on bigints
        if (left.kind() == ConstSlot.Kind.INT && right.kind() == ConstSlot.Kind.INT) {
            BigInteger a = left.bigInt();
            BigInteger b = right.bigInt();
            switch (op) {
                case "+": return ConstSlot.ofInt(a.add(b));
                case "-": return ConstSlot.ofInt(a.subtract(b));
                case "*": return ConstSlot.ofInt(a.multiply(b));
                case "/": {
                    if (b.signum() == 0) return null;
                    // Truncated toward zero (matches BigInteger.divide / JS BigInt).
                    return ConstSlot.ofInt(a.divide(b));
                }
                case "%": {
                    if (b.signum() == 0) return null;
                    // Sign follows dividend (matches BigInteger.remainder / JS BigInt).
                    return ConstSlot.ofInt(a.remainder(b));
                }
                case "===": return ConstSlot.ofBool(a.equals(b));
                case "!==": return ConstSlot.ofBool(!a.equals(b));
                case "<":  return ConstSlot.ofBool(a.compareTo(b) <  0);
                case ">":  return ConstSlot.ofBool(a.compareTo(b) >  0);
                case "<=": return ConstSlot.ofBool(a.compareTo(b) <= 0);
                case ">=": return ConstSlot.ofBool(a.compareTo(b) >= 0);
                case "&":  return ConstSlot.ofInt(a.and(b));
                case "|":  return ConstSlot.ofInt(a.or(b));
                case "^":  return ConstSlot.ofInt(a.xor(b));
                case "<<": {
                    if (a.signum() < 0) return null;        // BSV shifts are logical
                    if (b.signum() < 0) return null;
                    if (b.compareTo(BigInteger.valueOf(128)) > 0) return null;
                    return ConstSlot.ofInt(a.shiftLeft(b.intValue()));
                }
                case ">>": {
                    if (a.signum() < 0) return null;        // BSV shifts are logical
                    if (b.signum() < 0) return null;
                    if (b.compareTo(BigInteger.valueOf(128)) > 0) return null;
                    return ConstSlot.ofInt(a.shiftRight(b.intValue()));
                }
                default: return null;
            }
        }

        // Boolean operations
        if (left.kind() == ConstSlot.Kind.BOOL && right.kind() == ConstSlot.Kind.BOOL) {
            switch (op) {
                case "&&":  return ConstSlot.ofBool(left.boolVal() && right.boolVal());
                case "||":  return ConstSlot.ofBool(left.boolVal() || right.boolVal());
                case "===": return ConstSlot.ofBool(left.boolVal() == right.boolVal());
                case "!==": return ConstSlot.ofBool(left.boolVal() != right.boolVal());
                default: return null;
            }
        }

        // String (ByteString) operations
        if (left.kind() == ConstSlot.Kind.STR && right.kind() == ConstSlot.Kind.STR) {
            switch (op) {
                case "+":
                    if (!isValidHex(left.strVal()) || !isValidHex(right.strVal())) return null;
                    return ConstSlot.ofStr(left.strVal() + right.strVal());
                case "===": return ConstSlot.ofBool(left.strVal().equals(right.strVal()));
                case "!==": return ConstSlot.ofBool(!left.strVal().equals(right.strVal()));
                default: return null;
            }
        }

        // Cross-type equality
        if ("===".equals(op)) return ConstSlot.ofBool(false);
        if ("!==".equals(op)) return ConstSlot.ofBool(true);
        return null;
    }

    private static boolean isValidHex(String s) {
        if (s == null) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    // ---------------------------------------------------------------
    // Unary operation evaluation
    // ---------------------------------------------------------------

    private static ConstSlot evalUnaryOp(String op, ConstSlot operand) {
        if (operand.kind() == ConstSlot.Kind.BOOL) {
            if ("!".equals(op)) return ConstSlot.ofBool(!operand.boolVal());
            return null;
        }
        if (operand.kind() == ConstSlot.Kind.INT) {
            BigInteger n = operand.bigInt();
            switch (op) {
                case "-": return ConstSlot.ofInt(n.negate());
                case "~": return ConstSlot.ofInt(n.not());
                case "!": return ConstSlot.ofBool(n.signum() == 0);
                default: return null;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    // Builtin call evaluation (pure math functions only)
    // ---------------------------------------------------------------

    private static final BigInteger TEN_THOUSAND = BigInteger.valueOf(10_000);
    private static final BigInteger TWO_FIFTY_SIX = BigInteger.valueOf(256);

    private static ConstSlot evalBuiltinCall(String funcName, List<ConstSlot> args) {
        // All math builtins require integer args.
        List<BigInteger> ints = new ArrayList<>(args.size());
        for (ConstSlot a : args) {
            if (a.kind() != ConstSlot.Kind.INT) return null;
            ints.add(a.bigInt());
        }

        switch (funcName) {
            case "abs": {
                if (ints.size() != 1) return null;
                return ConstSlot.ofInt(ints.get(0).abs());
            }
            case "min": {
                if (ints.size() != 2) return null;
                return ConstSlot.ofInt(ints.get(0).min(ints.get(1)));
            }
            case "max": {
                if (ints.size() != 2) return null;
                return ConstSlot.ofInt(ints.get(0).max(ints.get(1)));
            }
            case "safediv": {
                if (ints.size() != 2 || ints.get(1).signum() == 0) return null;
                return ConstSlot.ofInt(ints.get(0).divide(ints.get(1)));
            }
            case "safemod": {
                if (ints.size() != 2 || ints.get(1).signum() == 0) return null;
                return ConstSlot.ofInt(ints.get(0).remainder(ints.get(1)));
            }
            case "clamp": {
                if (ints.size() != 3) return null;
                BigInteger val = ints.get(0), lo = ints.get(1), hi = ints.get(2);
                if (val.compareTo(lo) < 0) return ConstSlot.ofInt(lo);
                if (val.compareTo(hi) > 0) return ConstSlot.ofInt(hi);
                return ConstSlot.ofInt(val);
            }
            case "sign": {
                if (ints.size() != 1) return null;
                return ConstSlot.ofInt(BigInteger.valueOf(ints.get(0).signum()));
            }
            case "pow": {
                if (ints.size() != 2) return null;
                BigInteger base = ints.get(0);
                BigInteger exp = ints.get(1);
                if (exp.signum() < 0) return null;
                if (exp.compareTo(TWO_FIFTY_SIX) > 0) return null;
                BigInteger result = BigInteger.ONE;
                int e = exp.intValue();
                for (int i = 0; i < e; i++) {
                    result = result.multiply(base);
                }
                return ConstSlot.ofInt(result);
            }
            case "mulDiv": {
                if (ints.size() != 3 || ints.get(2).signum() == 0) return null;
                BigInteger tmp = ints.get(0).multiply(ints.get(1));
                return ConstSlot.ofInt(tmp.divide(ints.get(2)));
            }
            case "percentOf": {
                if (ints.size() != 2) return null;
                BigInteger tmp = ints.get(0).multiply(ints.get(1));
                return ConstSlot.ofInt(tmp.divide(TEN_THOUSAND));
            }
            case "sqrt": {
                if (ints.size() != 1) return null;
                BigInteger n = ints.get(0);
                if (n.signum() < 0) return null;
                if (n.signum() == 0) return ConstSlot.ofInt(BigInteger.ZERO);
                return ConstSlot.ofInt(n.sqrt());
            }
            case "gcd": {
                if (ints.size() != 2) return null;
                return ConstSlot.ofInt(ints.get(0).gcd(ints.get(1)));
            }
            case "divmod": {
                if (ints.size() != 2 || ints.get(1).signum() == 0) return null;
                return ConstSlot.ofInt(ints.get(0).divide(ints.get(1)));
            }
            case "log2": {
                if (ints.size() != 1) return null;
                BigInteger n = ints.get(0);
                if (n.signum() <= 0) return ConstSlot.ofInt(BigInteger.ZERO);
                return ConstSlot.ofInt(BigInteger.valueOf(n.bitLength() - 1));
            }
            case "bool": {
                if (ints.size() != 1) return null;
                return ConstSlot.ofBool(ints.get(0).signum() != 0);
            }
            default: return null;
        }
    }
}
