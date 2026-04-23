package runar.compiler.ir.anf;

import java.util.List;

public record Call(String func, List<String> args) implements AnfValue {
    @Override
    public String kind() {
        return "call";
    }
}
