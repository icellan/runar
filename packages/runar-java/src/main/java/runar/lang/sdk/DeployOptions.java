package runar.lang.sdk;

/**
 * Optional knobs for {@link RunarContract#deploy(Provider, Signer, DeployOptions)}.
 * All fields are nullable; pass {@code null} (or use the positional
 * {@code deploy} overloads) for the default flow (1 satoshi locked, change
 * to the deploy signer's address, funding inputs signed by the deploy signer).
 *
 * <p>Parity target: TypeScript {@code DeployOptions} (runar-sdk
 * {@code types.ts}).
 */
public final class DeployOptions {

    /** Satoshis to lock in the contract UTXO. {@code null} → 1. */
    public final Long satoshis;

    /**
     * P2PKH change address for the funding surplus. {@code null} → the
     * deploy signer's own address.
     */
    public final String changeAddress;

    /**
     * Signer for the P2PKH funding inputs (issue #134). When the funding
     * UTXOs are owned by a different key than the connected deploy signer,
     * set this so the funding inputs are signed by their real owner. The
     * funding-UTXO lookup still uses the deploy signer's address (mirroring
     * the TS SDK). {@code null} → the deploy signer (zero behaviour change).
     */
    public final Signer fundingSigner;

    /**
     * Builtins the caller accepts despite the compiler not claiming they are
     * sound (R-062). Required — naming each one — when the artifact declares
     * {@code unsoundPrimitives}; ignored otherwise.
     */
    public final java.util.List<String> acknowledgeUnsound;

    public DeployOptions(Long satoshis, String changeAddress, Signer fundingSigner) {
        this(satoshis, changeAddress, fundingSigner, null);
    }

    public DeployOptions(
        Long satoshis,
        String changeAddress,
        Signer fundingSigner,
        java.util.List<String> acknowledgeUnsound
    ) {
        this.satoshis = satoshis;
        this.changeAddress = changeAddress;
        this.fundingSigner = fundingSigner;
        this.acknowledgeUnsound = acknowledgeUnsound == null
            ? java.util.List.of()
            : java.util.List.copyOf(acknowledgeUnsound);
    }

    /** Empty options — every field defaulted. */
    public DeployOptions() {
        this(null, null, null, null);
    }

    // ------------------------------------------------------------------
    // Immutable "wither" copies for setting individual optional fields.
    // ------------------------------------------------------------------

    /** Copy with {@link #satoshis} set. */
    public DeployOptions withSatoshis(Long satoshis) {
        return new DeployOptions(satoshis, changeAddress, fundingSigner, acknowledgeUnsound);
    }

    /** Copy with {@link #changeAddress} set. */
    public DeployOptions withChangeAddress(String changeAddress) {
        return new DeployOptions(satoshis, changeAddress, fundingSigner, acknowledgeUnsound);
    }

    /** Copy with {@link #fundingSigner} set (issue #134). */
    public DeployOptions withFundingSigner(Signer fundingSigner) {
        return new DeployOptions(satoshis, changeAddress, fundingSigner, acknowledgeUnsound);
    }

    /** Copy with {@link #acknowledgeUnsound} set (R-062). */
    public DeployOptions withAcknowledgeUnsound(java.util.List<String> acknowledgeUnsound) {
        return new DeployOptions(satoshis, changeAddress, fundingSigner, acknowledgeUnsound);
    }
}
