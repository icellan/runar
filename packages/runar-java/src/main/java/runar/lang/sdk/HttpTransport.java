package runar.lang.sdk;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Package-private HTTP transport seam used by the on-chain
 * {@link Provider} implementations. The default implementation is
 * backed by {@link java.net.http.HttpClient}; tests inject a fake
 * to assert request-shape and feed canned responses.
 *
 * <p>Kept intentionally narrow — no streaming, no async — because
 * SDK calls are short request/response round-trips.
 */
interface HttpTransport {

    /**
     * Issues a single HTTP request and returns the raw response.
     *
     * @param method  HTTP verb ({@code "GET"} or {@code "POST"})
     * @param url     absolute request URL
     * @param headers request headers; {@code null} is treated as empty
     * @param body    request body for POST; ignored for GET; may be {@code null}
     */
    Response send(String method, String url, Map<String, String> headers, String body);

    /** HTTP response holder. */
    record Response(int statusCode, String body) {}

    /** Default transport backed by {@link HttpClient}. */
    static HttpTransport jdkDefault() {
        return JdkHttpTransport.INSTANCE;
    }

    final class JdkHttpTransport implements HttpTransport {
        static final JdkHttpTransport INSTANCE = new JdkHttpTransport();

        private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();

        private JdkHttpTransport() {}

        @Override
        public Response send(String method, String url, Map<String, String> headers, String body) {
            HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMinutes(10));
            if (headers != null) {
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    b.header(e.getKey(), e.getValue());
                }
            }
            String verb = method == null ? "GET" : method.toUpperCase();
            switch (verb) {
                case "GET" -> b.GET();
                case "POST" -> b.POST(body == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(body));
                default -> throw new ProviderException("Unsupported HTTP method: " + method);
            }
            try {
                HttpResponse<String> resp = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
                return new Response(resp.statusCode(), resp.body() == null ? "" : resp.body());
            } catch (IOException ioe) {
                throw new ProviderException("HTTP " + verb + " " + url + " failed: " + ioe.getMessage(), ioe);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new ProviderException("HTTP " + verb + " " + url + " interrupted", ie);
            }
        }
    }
}
