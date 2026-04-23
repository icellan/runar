package runar.compiler.ir.anf;

import java.util.List;

public record MethodCall(String object, String method, List<String> args) implements AnfValue {
    @Override
    public String kind() {
        return "method_call";
    }
}
