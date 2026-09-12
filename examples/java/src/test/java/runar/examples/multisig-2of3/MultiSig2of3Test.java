package runar.examples.multisig2of3;

import org.junit.jupiter.api.Test;
import runar.lang.sdk.CompileCheck;
import runar.lang.types.PubKey;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;

/**
 * R-107 — `multisig-2of3` is the canonical checkMultiSig + array-literal example
 * and was tested in four of the nine formats (ts, sol, move, zig). This is the
 * Java half.
 *
 * <p>{@code checkMultiSig(new Sig[]{...}, new PubKey[]{...})} lowers to two
 * {@code array_literal} ANF nodes — the canonical site where that node kind is
 * emitted at all, and one of the four kinds {@code spec/ir-format.md} did not
 * document until R-098.
 */
class MultiSig2of3Test {

    private static PubKey key(String fill) {
        return PubKey.fromHex("02" + fill.repeat(32));
    }

    @Test
    void contractInstantiatesWithThreeDistinctKeys() {
        PubKey a = key("11");
        PubKey b = key("22");
        PubKey c = key("33");
        MultiSig2of3 contract = new MultiSig2of3(a, b, c);

        assertNotNull(contract);
        // The 2-of-3 shape is the point: three separate pubkey slots. A contract
        // that collapsed them would still construct.
        assertNotSame(contract.pk1, contract.pk2);
        assertNotSame(contract.pk2, contract.pk3);
    }

    @Test
    void compilesThroughTheRunarFrontend() throws Exception {
        CompileCheck.run(Path.of("src/main/java/runar/examples/multisig-2of3/MultiSig2of3.runar.java"));
    }
}
