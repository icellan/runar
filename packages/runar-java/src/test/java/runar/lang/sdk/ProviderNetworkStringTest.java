package runar.lang.sdk;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * R-051: an unrecognised, empty, or null network string must never silently
 * select mainnet. Assertions are on the RESOLVED ENDPOINT URL, not on an
 * internal flag.
 */
final class ProviderNetworkStringTest {

    /** Values a caller can plausibly pass by mistake. */
    private static final List<String> BAD_NETWORKS =
        java.util.Arrays.asList(null, "", " ", "mainnett", "MAINNET", "Mainnet", "testnett", "regtest", "main");

    @Test
    void whatsOnChainBadNetworkNeverResolvesMainnet() {
        for (String network : BAD_NETWORKS) {
            String baseUrl;
            try {
                baseUrl = new WhatsOnChainProvider(network).getBaseUrl();
            } catch (IllegalArgumentException e) {
                continue; // rejected — acceptable
            }
            if (baseUrl.contains("/bsv/main")) {
                fail("network " + quote(network) + " resolved to a MAINNET endpoint "
                    + baseUrl + " (fail-open)");
            }
        }
    }

    @Test
    void gorillaPoolBadNetworkNeverResolvesMainnet() {
        for (String network : BAD_NETWORKS) {
            String baseUrl;
            try {
                baseUrl = new GorillaPoolProvider(network).getBaseUrl();
            } catch (IllegalArgumentException e) {
                continue; // rejected — acceptable
            }
            if (baseUrl.startsWith("https://ordinals.gorillapool.io")) {
                fail("network " + quote(network) + " resolved to a MAINNET endpoint "
                    + baseUrl + " (fail-open)");
            }
        }
    }

    /** Control: the fix must not be satisfiable by disabling mainnet entirely. */
    @Test
    void explicitNetworksStillResolveTheirOwnEndpoints() {
        assertEquals("https://api.whatsonchain.com/v1/bsv/main",
            new WhatsOnChainProvider("mainnet").getBaseUrl());
        assertEquals("https://api.whatsonchain.com/v1/bsv/test",
            new WhatsOnChainProvider("testnet").getBaseUrl());
        assertEquals("https://ordinals.gorillapool.io/api",
            new GorillaPoolProvider("mainnet").getBaseUrl());
        assertEquals("https://testnet.ordinals.gorillapool.io/api",
            new GorillaPoolProvider("testnet").getBaseUrl());
    }

    /** The rejection message must name the offending value and the accepted set. */
    @Test
    void rejectionMessageIsActionable() {
        IllegalArgumentException woc = org.junit.jupiter.api.Assertions.assertThrows(
            IllegalArgumentException.class, () -> new WhatsOnChainProvider("mainnett"));
        org.junit.jupiter.api.Assertions.assertTrue(woc.getMessage().contains("mainnett"), woc.getMessage());
        org.junit.jupiter.api.Assertions.assertTrue(woc.getMessage().contains("testnet"), woc.getMessage());

        IllegalArgumentException gp = org.junit.jupiter.api.Assertions.assertThrows(
            IllegalArgumentException.class, () -> new GorillaPoolProvider((String) null));
        org.junit.jupiter.api.Assertions.assertTrue(gp.getMessage().contains("null"), gp.getMessage());
        org.junit.jupiter.api.Assertions.assertTrue(gp.getMessage().contains("testnet"), gp.getMessage());
    }

    private static String quote(String s) {
        return s == null ? "null" : "\"" + s + "\"";
    }
}
