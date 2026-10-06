package runar.lang.sdk;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * N-025: GorillaPoolProvider must call the routes the GorillaPool API actually
 * serves, decode their documented shapes, and surface a 404 as an error. The
 * old routes (/tx/{txid}/hex, /address/{a}/utxos, /script/{h}/utxos,
 * /bsv20/balance/..., /bsv20/utxos/...) do not exist, and the provider mapped
 * their 404 to an empty list / "0".
 *
 * <p>Proves: replaying the shared recorded responses
 * (conformance/sdk-gorillapool/endpoint-vectors.json, recorded 2026-10-05)
 * through the transport + raw-fetch seams, every call Java has decodes to the
 * independently derived expectation, every unrouted (404) request throws,
 * tampered bodies (txid mismatch, listing value != raw tx value) are refused,
 * getContractUtxos refuses without a request (no documented route), and
 * broadcastRaw posts exactly {"rawtx": hex}.
 *
 * <p>Does NOT prove: that the live API still serves these shapes; that POST
 * /api/tx accepts {"rawtx"} (schema-documented, never sent live); pagination
 * beyond the API's default page (100). The inscription calls in the vector
 * file are skipped in this tier: the Java provider has no inscription methods.
 */
class N025GorillaPoolEndpointsTest {

    private static final String HOST = "https://ordinals.gorillapool.io";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> load() throws Exception {
        Path p = Paths.get(System.getProperty("user.dir"),
            "..", "..", "conformance", "sdk-gorillapool", "endpoint-vectors.json");
        return (Map<String, Object>) Json.parse(Files.readString(p));
    }

    /** Serves the recorded routes over both seams; anything else gets the recorded 404. */
    private static final class Router implements HttpTransport, GorillaPoolProvider.RawFetcher {
        final List<Map<String, Object>> routes;
        final Map<String, Object> notFound;
        final List<String> posted = new ArrayList<>();
        int requests;

        Router(List<Map<String, Object>> routes, Map<String, Object> notFound) {
            this.routes = routes;
            this.notFound = notFound;
        }

        private Map<String, Object> find(String method, String url) {
            requests++;
            for (Map<String, Object> r : routes) {
                if (method.equals(r.get("method")) && url.equals(HOST + r.get("path"))) return r;
            }
            return notFound;
        }

        private static byte[] bytes(Map<String, Object> r) {
            return ScriptUtils.hexToBytes((String) r.get("bodyHex"));
        }

        @Override
        public Response send(String method, String url, Map<String, String> headers, String body) {
            String m = method == null ? "GET" : method.toUpperCase();
            if ("POST".equals(m)) posted.add(body);
            Map<String, Object> r = find(m, url);
            return new Response(Json.asInt(r.get("status")), new String(bytes(r), StandardCharsets.UTF_8));
        }

        @Override
        public GorillaPoolProvider.RawResponse get(String url) {
            Map<String, Object> r = find("GET", url);
            return new GorillaPoolProvider.RawResponse(Json.asInt(r.get("status")), bytes(r));
        }
    }

    private static List<Map<String, Object>> utxoMaps(List<UTXO> us) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (UTXO u : us) {
            out.add(Map.of("txid", u.txid(), "outputIndex", (long) u.outputIndex(),
                "satoshis", u.satoshis(), "script", u.scriptHex()));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Object normalize(Object expect) {
        if (expect instanceof List<?> l) {
            List<Map<String, Object>> out = new ArrayList<>();
            for (Object o : l) {
                Map<String, Object> m = (Map<String, Object>) o;
                out.add(Map.of("txid", m.get("txid"), "outputIndex", Json.asLong(m.get("outputIndex")),
                    "satoshis", Json.asLong(m.get("satoshis")), "script", m.get("script")));
            }
            return out;
        }
        return expect;
    }

    /** Returns null when this tier has no such call. */
    private static Object invoke(GorillaPoolProvider p, String call, List<Object> a) {
        switch (call) {
            case "getRawTransaction": return p.getRawTransaction((String) a.get(0));
            case "getUtxos": return utxoMaps(p.listUtxos((String) a.get(0)));
            case "getContractUtxo": return utxoMaps(p.getContractUtxos((String) a.get(0)));
            case "getBSV20Balance": return p.getBSV20Balance((String) a.get(0), (String) a.get(1));
            case "getBSV21Balance": return p.getBSV21Balance((String) a.get(0), (String) a.get(1));
            case "getBSV20Utxos": return utxoMaps(p.getBSV20Utxos((String) a.get(0), (String) a.get(1)));
            case "getBSV21Utxos": return utxoMaps(p.getBSV21Utxos((String) a.get(0), (String) a.get(1)));
            case "broadcast": return p.broadcastRaw((String) a.get(0));
            default: return null;
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void replaysEveryApplicableRecordedCall() throws Exception {
        Map<String, Object> doc = load();
        List<Map<String, Object>> routes = (List<Map<String, Object>>) doc.get("routes");
        Map<String, Object> notFound = (Map<String, Object>) doc.get("notFound");
        List<Map<String, Object>> calls = (List<Map<String, Object>>) doc.get("calls");
        assertTrue(calls.size() >= 27);

        List<String> failures = new ArrayList<>();
        int replayed = 0;
        for (int i = 0; i < calls.size(); i++) {
            Map<String, Object> c = calls.get(i);
            String call = (String) c.get("call");
            List<Object> args = (List<Object>) c.get("args");
            String label = "#" + i + " " + call + args;
            Router router = new Router(routes, notFound);
            GorillaPoolProvider p = new GorillaPoolProvider("mainnet", router, router);
            if (call.startsWith("getInscription")) continue; // no inscription API in the Java tier
            replayed++;
            String expectError = (String) c.get("expectError");
            try {
                Object got = invoke(p, call, args);
                if (expectError != null) {
                    failures.add(label + ": expected error containing '" + expectError + "', got " + got);
                    continue;
                }
                if (!normalize(c.get("expect")).equals(got)) {
                    failures.add(label + ": expected " + c.get("expect") + ", got " + got);
                    continue;
                }
            } catch (RuntimeException e) {
                if (expectError == null || e.getMessage() == null || !e.getMessage().contains(expectError)) {
                    failures.add(label + ": unexpected " + e);
                }
                if (expectError != null && "not supported".equals(expectError) && router.requests != 0) {
                    failures.add(label + ": refused but still made " + router.requests + " request(s)");
                }
                continue;
            }
            Object reqJson = c.get("expectRequestJson");
            if (reqJson != null) {
                if (router.posted.size() != 1 || !reqJson.equals(Json.parse(router.posted.get(0)))) {
                    failures.add(label + ": posted " + router.posted + ", expected " + reqJson);
                }
            }
        }
        assertEquals(20, replayed, "applicable calls replayed");
        assertTrue(failures.isEmpty(), failures.size() + " failure(s):\n" + String.join("\n", failures));
    }
}
