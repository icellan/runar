package runar.lang.sdk;

import java.util.List;

/**
 * One output of a BRC-100 {@code createAction}. Parity with the Go SDK's
 * {@code WalletActionOutput}.
 *
 * @param lockingScript locking script hex
 * @param satoshis      output value
 * @param description   human-readable output description
 * @param basket        wallet basket to track the output in (may be empty)
 * @param tags          output tags (never {@code null}; empty when none)
 */
public record WalletActionOutput(
    String lockingScript,
    long satoshis,
    String description,
    String basket,
    List<String> tags
) {
    public WalletActionOutput {
        tags = tags == null ? List.of() : List.copyOf(tags);
    }
}
