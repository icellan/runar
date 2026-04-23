package runar.compiler.ir.anf;

import java.util.List;

public record Loop(int count, List<AnfBinding> body, String iterVar) implements AnfValue {
    @Override
    public String kind() {
        return "loop";
    }
}
