package runar.compiler.ir.anf;

import java.util.List;

/**
 * Adds a state-continuation output. {@code stateValues} must reference
 * temporaries in the order of the contract's mutable properties at
 * declaration time; {@code preimage} references the verified preimage
 * temp used to splice in the current {@code codePart}.
 */
public record AddOutput(String satoshis, List<String> stateValues, String preimage) implements AnfValue {
    @Override
    public String kind() {
        return "add_output";
    }
}
