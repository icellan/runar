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
import runar.compiler.ir.anf.UnaryOp;
import runar.compiler.ir.anf.UpdateProp;

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
        return new AnfProgram(name, props, methods);
    }

    private static AnfProperty toProperty(Map<?, ?> obj) {
        String name = asString(obj.get("name"));
        String type = asString(obj.get("type"));
        boolean readonly = Boolean.TRUE.equals(obj.get("readonly"));
        ConstValue initial = null;
        Object iv = obj.get("initialValue");
        if (iv != null) initial = toConst(iv);
        return new AnfProperty(name, type, readonly, initial);
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

    private static AnfBinding toBinding(Map<?, ?> obj) {
        String name = asString(obj.get("name"));
        AnfValue v = toValue(asObject(obj.get("value")));
        return new AnfBinding(name, v, null);
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
                toBindingList(obj.get("else"))
            );
            case "loop" -> new Loop(
                asInt(obj.get("count")),
                toBindingList(obj.get("body")),
                asString(obj.get("iterVar"))
            );
            case "assert" -> new Assert(asString(obj.get("value")));
            case "update_prop" -> new UpdateProp(asString(obj.get("name")), asString(obj.get("value")));
            case "get_state_script" -> new GetStateScript();
            case "check_preimage" -> new CheckPreimage(asString(obj.get("preimage")));
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
            default -> throw new RuntimeException("unknown ANF value kind: " + kind);
        };
    }

    private static ConstValue toConst(Object v) {
        if (v instanceof Boolean b) return new BoolConst(b);
        if (v instanceof BigInteger bi) return new BigIntConst(bi);
        if (v instanceof Long l) return new BigIntConst(BigInteger.valueOf(l));
        if (v instanceof Integer i) return new BigIntConst(BigInteger.valueOf(i));
        if (v instanceof String s) return new BytesConst(s);
        throw new RuntimeException("unexpected const type: " + (v == null ? "null" : v.getClass()));
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

    private static int asInt(Object v) {
        if (v instanceof Long l) return l.intValue();
        if (v instanceof Integer i) return i;
        if (v instanceof BigInteger bi) return bi.intValue();
        throw new RuntimeException("expected int, got " + (v == null ? "null" : v.getClass()));
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
