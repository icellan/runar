package runar.compiler.ir;

/**
 * Raised by ANF dispatch when it encounters a kind it doesn't handle.
 *
 * <p>Historically each ANF dispatcher used an implicit fall-through (an
 * if/else-if chain with no final {@code else}, a {@code default -> {}}
 * arrow, or a trailing {@code return value;}) that turned an unrecognised
 * kind into a silent no-op. Adding a new {@link runar.compiler.ir.anf.AnfValue}
 * variant and forgetting to wire it into all dispatch sites would then
 * silently corrupt downstream IR (empty refs list -> wrong PICK/ROLL,
 * unchanged value -> dropped binding) instead of failing loudly.
 *
 * <p>Every former silent default now throws this typed error so the
 * regression is caught at the first dispatch site instead of leaking into
 * Stack IR / hex. Mirrors {@code UnknownANFKindError} in
 * {@code packages/runar-ir-schema/src/unknown-anf-kind-error.ts}.
 *
 * <p>See {@code CLAUDE.md § Adding a New ANF Value Kind} for the cross-tier
 * dispatch-site recipe that must be followed when introducing a variant.
 */
public class UnknownAnfKindError extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String kind;
    private final String location;

    public UnknownAnfKindError(String kind, String location) {
        super("unknown ANF kind '" + kind + "' encountered in " + location
            + " — if you added a new ANFValue variant, update all dispatch sites "
            + "(see CLAUDE.md § Adding a New ANF Value Kind)");
        this.kind = kind;
        this.location = location;
    }

    public String getKind() {
        return kind;
    }

    public String getLocation() {
        return location;
    }
}
