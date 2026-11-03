package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import runar.compiler.Cli;
import runar.compiler.ir.anf.AnfProgram;

/**
 * F-084 (CX-BUG-046) — the {@code --ir} loader must REFUSE a missing or
 * wrongly-typed required field instead of defaulting it.
 *
 * <p>Before the fix, every collection branch in {@code AnfLoader} populated a
 * fresh empty list only when the JSON value was already an array, and every
 * string accessor returned {@code null} for an absent key. So a public method
 * whose {@code body} was {@code "not-an-array"} (or simply omitted) loaded as a
 * public method with ZERO bindings, passed every downstream check (they all
 * iterate the bindings and find nothing to object to), and {@code --ir --hex}
 * exited 0 with a locking script that carries none of the method's guards.
 *
 * <p>What this proves: each adversarial shape below — every one of them the
 * valid control with ONE field changed — is refused by {@code AnfLoader.parse}
 * with a diagnostic that names the malformed field's path, and the CLI's
 * {@code --ir --hex} mode exits nonzero for the brief's headline case.
 *
 * <p>What this does not prove: that every schema constraint in
 * {@code packages/runar-ir-schema/src/schemas/anf-ir.schema.json} is enforced
 * (optional-with-default fields the loader tolerates on purpose — loop
 * {@code start}/{@code step}, add_output {@code preimage}, {@code results} —
 * are unchanged), nor anything about the other six tiers' IR loaders.
 */
class F084IrRequiredFieldsTest {

    /** Valid single-public-method IR; every case below edits one field. */
    private static final String CONTROL = """
        {"contractName":"X","properties":[{"name":"pk","type":"PubKey","readonly":true}],"methods":[
          {"name":"unlock","isPublic":true,"params":[{"name":"sig","type":"Sig"}],"body":[
            {"name":"t0","value":{"kind":"load_param","name":"sig"}},
            {"name":"t1","value":{"kind":"load_prop","name":"pk"}},
            {"name":"t2","value":{"kind":"call","func":"checkSig","args":["t0","t1"]}},
            {"name":"t3","value":{"kind":"assert","value":"t2"}}
          ]}
        ]}
        """;

    private static void assertRefused(String json, String fieldPath) {
        RuntimeException ex = assertThrows(RuntimeException.class, () -> AnfLoader.parse(json));
        assertTrue(ex.getMessage() != null && ex.getMessage().contains(fieldPath),
            "diagnostic should name '" + fieldPath + "': " + ex.getMessage());
    }

    private static String edit(String from, String to) {
        assertTrue(CONTROL.contains(from), "probe edit does not apply: " + from);
        return CONTROL.replace(from, to);
    }

    private static final String BODY_START = "\"body\":[";
    private static final String BODY_ALL = CONTROL.substring(
        CONTROL.indexOf(BODY_START), CONTROL.indexOf("]}\n]}") + 1);

    @Test
    void controlIsAccepted() {
        AnfProgram p = AnfLoader.parse(CONTROL);
        assertEquals(4, p.methods().get(0).body().size());
    }

    @Test
    void bodyNotAnArrayIsRefused() {
        assertRefused(edit(BODY_ALL, "\"body\":\"not-an-array\""), "methods[0].body");
    }

    @Test
    void bodyOmittedIsRefused() {
        assertRefused(edit("\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}]," + BODY_ALL,
            "\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}]"), "methods[0].body");
    }

    @Test
    void paramsAsObjectIsRefused() {
        assertRefused(edit("\"params\":[{\"name\":\"sig\",\"type\":\"Sig\"}]",
            "\"params\":{\"name\":\"sig\",\"type\":\"Sig\"}"), "methods[0].params");
    }

    @Test
    void paramTypeMissingIsRefused() {
        assertRefused(edit("{\"name\":\"sig\",\"type\":\"Sig\"}", "{\"name\":\"sig\"}"),
            "methods[0].params[0].type");
    }

    @Test
    void methodNameMissingIsRefused() {
        assertRefused(edit("{\"name\":\"unlock\",", "{"), "methods[0].name");
    }

    @Test
    void isPublicWronglyTypedIsRefused() {
        assertRefused(edit("\"isPublic\":true", "\"isPublic\":\"true\""), "methods[0].isPublic");
    }

    @Test
    void propertiesAsObjectIsRefused() {
        assertRefused(edit("\"properties\":[{\"name\":\"pk\",\"type\":\"PubKey\",\"readonly\":true}]",
            "\"properties\":{}"), "properties");
    }

    @Test
    void propertiesOmittedIsRefused() {
        assertRefused(edit("\"properties\":[{\"name\":\"pk\",\"type\":\"PubKey\",\"readonly\":true}],", ""),
            "properties");
    }

    @Test
    void propertyReadonlyMissingIsRefused() {
        // A missing `readonly` used to read as mutable, silently changing the
        // contract's state layout.
        assertRefused(edit(",\"readonly\":true", ""), "properties[0].readonly");
    }

    @Test
    void propertyNameMissingIsRefused() {
        assertRefused(edit("{\"name\":\"pk\",\"type\":\"PubKey\"", "{\"type\":\"PubKey\""),
            "properties[0].name");
    }

    @Test
    void methodsAsObjectIsRefused() {
        String json = "{\"contractName\":\"X\",\"properties\":{},\"methods\":{}}";
        assertRefused(json, "properties");
        assertRefused("{\"contractName\":\"X\",\"properties\":[],\"methods\":{}}", "methods");
    }

    @Test
    void contractNameMissingIsRefused() {
        assertRefused(edit("\"contractName\":\"X\",", ""), "contractName");
    }

    @Test
    void bindingNameMissingIsRefused() {
        assertRefused(edit("{\"name\":\"t3\",", "{"), "methods[0].body[3].name");
    }

    @Test
    void valueKindMissingIsRefused() {
        assertRefused(edit("{\"kind\":\"assert\",", "{"), "methods[0].body[3].value.kind");
    }

    @Test
    void assertOperandMissingIsRefused() {
        assertRefused(edit("{\"kind\":\"assert\",\"value\":\"t2\"}", "{\"kind\":\"assert\"}"),
            "methods[0].body[3].value.value");
    }

    @Test
    void callArgsNotAnArrayIsRefused() {
        assertRefused(edit("\"args\":[\"t0\",\"t1\"]", "\"args\":\"t0\""),
            "methods[0].body[2].value.args");
    }

    @Test
    void nestedIfArmNotAnArrayIsRefused() {
        assertRefused(edit("{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}",
            "{\"name\":\"t3\",\"value\":{\"kind\":\"if\",\"cond\":\"t2\",\"then\":\"x\",\"else\":[]}}"),
            "methods[0].body[3].value.then");
    }

    @Test
    void nestedLoopBodyMissingIsRefused() {
        assertRefused(edit("{\"name\":\"t3\",\"value\":{\"kind\":\"assert\",\"value\":\"t2\"}}",
            "{\"name\":\"t3\",\"value\":{\"kind\":\"loop\",\"count\":2,\"iterVar\":\"i\"}}"),
            "methods[0].body[3].value.body");
    }

    /** The brief's headline assertion, end to end through the CLI. */
    @Test
    void cliIrHexRefusesBodyNotAnArray() throws Exception {
        Path ok = Files.createTempFile("f084-ok", ".json");
        Path bad = Files.createTempFile("f084-bad", ".json");
        try {
            Files.writeString(ok, CONTROL);
            Files.writeString(bad, edit(BODY_ALL, "\"body\":\"not-an-array\""));
            String[] okRun = runCli("--ir", ok.toString(), "--hex");
            assertEquals("0", okRun[0], "control must compile: " + okRun[2]);
            String[] badRun = runCli("--ir", bad.toString(), "--hex");
            assertEquals("65", badRun[0], "stdout: " + badRun[1]);
            assertEquals("", badRun[1].trim(), "no artifact may be emitted");
            assertTrue(badRun[2].contains("methods[0].body"), badRun[2]);
        } finally {
            Files.deleteIfExists(ok);
            Files.deleteIfExists(bad);
        }
    }

    private static String[] runCli(String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        PrintStream o = new PrintStream(out, true, StandardCharsets.UTF_8);
        PrintStream e = new PrintStream(err, true, StandardCharsets.UTF_8);
        int exit = new Cli(o, e).run(args);
        return new String[] {
            Integer.toString(exit),
            out.toString(StandardCharsets.UTF_8),
            err.toString(StandardCharsets.UTF_8)
        };
    }
}
