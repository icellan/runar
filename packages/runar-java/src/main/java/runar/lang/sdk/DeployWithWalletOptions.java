package runar.lang.sdk;

import java.util.List;

/**
 * Options for {@link RunarContract#deployWithWallet}. Parity with the Go SDK's
 * {@code DeployWithWalletOptions}. Every field is optional.
 *
 * @param satoshis           value locked in the contract output; {@code null}
 *                           or {@code <= 0} means 1
 * @param description        action description; {@code null}/empty means
 *                           {@code "deploy <ContractName>"}
 * @param basket             basket for the contract output; {@code null}/empty
 *                           means the provider's basket
 * @param tags               tags for the contract output
 * @param acknowledgeUnsound builtins the caller accepts despite the compiler not
 *                           claiming they are sound (R-062); required, naming
 *                           each one, when the artifact declares any
 */
public record DeployWithWalletOptions(
    Long satoshis,
    String description,
    String basket,
    List<String> tags,
    List<String> acknowledgeUnsound
) {
    public DeployWithWalletOptions {
        tags = tags == null ? List.of() : List.copyOf(tags);
        acknowledgeUnsound = acknowledgeUnsound == null ? List.of() : List.copyOf(acknowledgeUnsound);
    }
}
