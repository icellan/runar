package runar.lang.sdk;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RunarArtifactTest {

    @Test
    void parsesBasicP2pkhArtifactFixture() throws Exception {
        Path fixture = locateFixture("artifacts/basic-p2pkh.runar.json");
        String json = Files.readString(fixture);
        RunarArtifact art = RunarArtifact.fromJson(json);

        assertEquals("runar-v0.1.0", art.version());
        assertEquals("0.1.0", art.compilerVersion());
        assertEquals("P2PKH", art.contractName());
        assertEquals("a9007c7c9c69007c7cac69", art.scriptHex());
        assertFalse(art.isStateful());
        assertEquals(1, art.abi().constructor().params().size());
        assertEquals("pubKeyHash", art.abi().constructor().params().get(0).name());
        assertEquals("Addr", art.abi().constructor().params().get(0).type());
        assertEquals(1, art.abi().methods().size());
        RunarArtifact.ABIMethod unlock = art.abi().methods().get(0);
        assertEquals("unlock", unlock.name());
        assertTrue(unlock.isPublic());
        assertEquals(2, unlock.params().size());
        assertEquals("sig", unlock.params().get(0).name());
        assertEquals("Sig", unlock.params().get(0).type());
    }

    @Test
    void parsesStatefulArtifactFixture() throws Exception {
        Path fixture = locateFixture("artifacts/stateful.runar.json");
        String json = Files.readString(fixture);
        RunarArtifact art = RunarArtifact.fromJson(json);

        assertEquals("Stateful", art.contractName());
        assertTrue(art.isStateful());
        assertEquals(1, art.stateFields().size());
        assertEquals("count", art.stateFields().get(0).name());
        assertEquals("bigint", art.stateFields().get(0).type());
        assertEquals(0, art.stateFields().get(0).index());
        assertTrue(art.abi().methods().stream().anyMatch(m -> "increment".equals(m.name())));
        assertTrue(art.abi().methods().stream().anyMatch(m -> "reset".equals(m.name())));
    }

    @Test
    void parsesJsonDirectlyWithoutArtifactWrapper() {
        String json = """
            {
              "version": "runar-v0.1.0",
              "compilerVersion": "0.1.0",
              "contractName": "T",
              "abi": {
                "constructor": { "params": [] },
                "methods": []
              },
              "script": "6a",
              "asm": "OP_RETURN",
              "buildTimestamp": "2026-01-01T00:00:00Z"
            }
            """;
        RunarArtifact art = RunarArtifact.fromJson(json);
        assertEquals("T", art.contractName());
        assertEquals("6a", art.scriptHex());
        assertTrue(art.abi().methods().isEmpty());
    }

    /** Loads a test fixture from the test-resources classpath. */
    private static Path locateFixture(String relative) {
        // Strip an "artifacts/" prefix so both legacy worktree-root paths
        // ("artifacts/foo.json") and direct names ("foo.json") resolve.
        String leaf = relative.startsWith("artifacts/")
            ? relative.substring("artifacts/".length())
            : relative;
        var url = RunarArtifactTest.class.getClassLoader().getResource("artifacts/" + leaf);
        if (url == null) {
            throw new IllegalStateException(
                "fixture not found on test classpath: artifacts/" + leaf
            );
        }
        try {
            return Path.of(url.toURI());
        } catch (java.net.URISyntaxException e) {
            throw new IllegalStateException("bad fixture URL for " + leaf, e);
        }
    }
}
