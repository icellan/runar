package runar.lang.sdk;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * R-062 / CL-BUG-105 — see {@link UnsoundPrimitives} for the finding.
 *
 * <p>Mirrors packages/runar-sdk/src/__tests__/unsound-primitives.test.ts.
 */
class UnsoundPrimitivesTest {

    private static RunarArtifact artifact(String... unsound) {
        return new RunarArtifact(
            "runar-v1.0.0-rc.1", "1.0.0-rc.1-go", "Sp1Rollup", null,
            new RunarArtifact.ABI(new RunarArtifact.ABIConstructor(List.of()), List.of()),
            "51", "OP_1", "2026-09-13T00:00:00Z",
            List.of(), List.of(), List.of(), null, List.of(), null,
            List.of(unsound)
        );
    }

    @Test
    void ordinaryArtifactDeploysEitherWay() {
        assertDoesNotThrow(() -> UnsoundPrimitives.assertAcknowledged(artifact(), null, "Counter.deploy"));
        assertDoesNotThrow(() -> UnsoundPrimitives.assertAcknowledged(artifact(), List.of(), "Counter.deploy"));
        assertDoesNotThrow(() ->
            UnsoundPrimitives.assertAcknowledged(artifact(), List.of("verifySP1FRI"), "Counter.deploy"));
        assertDoesNotThrow(() -> UnsoundPrimitives.assertAcknowledged(null, null, "Counter.deploy"));
    }

    @Test
    void refusesUnacknowledged() {
        var e = assertThrows(
            UnsoundPrimitives.UnsoundPrimitiveError.class,
            () -> UnsoundPrimitives.assertAcknowledged(artifact("verifySP1FRI"), null, "Sp1Rollup.deploy")
        );
        assertTrue(e.getMessage().contains("verifySP1FRI"), e.getMessage());
        assertTrue(e.getMessage().contains("Sp1Rollup.deploy"), e.getMessage());
        assertTrue(e.getMessage().contains("withAcknowledgeUnsound"), e.getMessage());
        assertEquals(List.of("verifySP1FRI"), e.missing);
    }

    @Test
    void acknowledgementMustNameEveryPrimitive() {
        assertDoesNotThrow(() -> UnsoundPrimitives.assertAcknowledged(
            artifact("verifySP1FRI"), List.of("verifySP1FRI"), "Sp1Rollup.deploy"));

        var e = assertThrows(
            UnsoundPrimitives.UnsoundPrimitiveError.class,
            () -> UnsoundPrimitives.assertAcknowledged(
                artifact("verifySP1FRI", "someFutureStub"), List.of("verifySP1FRI"), "Sp1Rollup.deploy")
        );
        assertEquals(List.of("someFutureStub"), e.missing);

        assertThrows(
            UnsoundPrimitives.UnsoundPrimitiveError.class,
            () -> UnsoundPrimitives.assertAcknowledged(
                artifact("verifySP1FRI"), List.of("somethingElse"), "Sp1Rollup.deploy")
        );
    }

    @Test
    void markerSurvivesArtifactJson() {
        RunarArtifact marked = RunarArtifact.fromJson(
            "{\"version\":\"v\",\"contractName\":\"Sp1Rollup\",\"script\":\"51\","
                + "\"abi\":{\"constructor\":{\"params\":[]},\"methods\":[]},"
                + "\"unsoundPrimitives\":[\"verifySP1FRI\"]}"
        );
        assertEquals(List.of("verifySP1FRI"), marked.unsoundPrimitives());

        RunarArtifact plain = RunarArtifact.fromJson(
            "{\"version\":\"v\",\"contractName\":\"Counter\",\"script\":\"51\","
                + "\"abi\":{\"constructor\":{\"params\":[]},\"methods\":[]}}"
        );
        assertTrue(plain.unsoundPrimitives().isEmpty());
    }

    @Test
    void deployOptionsCarriesTheAcknowledgement() {
        DeployOptions base = new DeployOptions();
        assertTrue(base.acknowledgeUnsound.isEmpty());

        DeployOptions acked = base.withAcknowledgeUnsound(List.of("verifySP1FRI"));
        assertEquals(List.of("verifySP1FRI"), acked.acknowledgeUnsound);
        // and the wither copies keep it
        assertEquals(List.of("verifySP1FRI"), acked.withSatoshis(5L).acknowledgeUnsound);
    }
}
