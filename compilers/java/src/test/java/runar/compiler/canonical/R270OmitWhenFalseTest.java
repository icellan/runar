package runar.compiler.canonical;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import runar.compiler.ir.anf.Assert;

/**
 * R-270 (CL-GAP-022): {@code @JsonOmitWhenFalse} exists so a component can opt
 * out of being serialized when false, declaratively. {@code Jcs} still omits
 * {@code Assert.isAutoInjectedStateCheck} by comparing the component's NAME to
 * a string literal instead.
 *
 * <p>Both mechanisms produce the same bytes today, which is exactly why this
 * survived: the string branch works. What it does not do is travel with the
 * field. Rename the record component, add a second field that needs the same
 * treatment, or port this record to another IR node, and the annotation moves
 * with the declaration while the string literal stays behind in the serializer —
 * and the canonical JSON silently grows a {@code "isAutoInjectedStateCheck":
 * false} that no other tier emits. The canonical form is compared across seven
 * tiers, so one extra key is a conformance failure, not a cosmetic one.
 *
 * <p>The finding says the annotation is "dead". That was true when it was
 * filed; {@code StackMethod.needsCodeSeparator} now carries it and {@code Jcs}
 * reads it. The residue is the older half: one field still omitted by name.
 */
class R270OmitWhenFalseTest {

    /** The serializer must not decide anything from a component's spelling. */
    @Test
    void jcsOmitsNothingByName() throws IOException {
        Path jcs = Path.of("src/main/java/runar/compiler/canonical/Jcs.java");
        List<String> offenders = Files.readAllLines(jcs).stream()
            .filter(l -> l.contains(".equals(rc.getName())"))
            .map(String::trim)
            .toList();
        assertTrue(
            offenders.isEmpty(),
            "Jcs decides omission from a component NAME: " + offenders
                + " — use @JsonOmitWhenFalse on the declaration so the rule "
                + "travels with the field it is about.");
    }

    /** The behaviour the string branch was providing, which must not change. */
    @Test
    void falseAutoInjectedMarkerIsOmitted() {
        String json = Jcs.stringify(new Assert("t3", false));
        assertFalse(
            json.contains("isAutoInjectedStateCheck"),
            "a false marker must not reach the canonical JSON; got " + json);
        assertEquals("{\"kind\":\"assert\",\"value\":\"t3\"}", json);
    }

    /** ...and a true marker must still be written, or the SDKs lose the signal. */
    @Test
    void trueAutoInjectedMarkerIsWritten() {
        String json = Jcs.stringify(new Assert("t3", true));
        assertTrue(
            json.contains("\"isAutoInjectedStateCheck\":true"),
            "a true marker must be serialized; got " + json);
    }
}
