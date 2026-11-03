package runar.compiler.passes;

import java.util.List;
import java.util.regex.Pattern;

/**
 * N-065 / N-060 — compiler-reserved names. Mirrors
 * {@code packages/runar-compiler/src/passes/reserved-names.ts} exactly (same
 * families, same sentence, shared verbatim by all seven tiers).
 *
 * <p>Passes mint names into the namespace user identifiers live in and every
 * later pass resolves a name by string equality, so a user name spelled like a
 * minted one aliases two values ({@code let t2 = p; ... if (c) { t2 = p; }}
 * read the ANF temp {@code t2} when {@code c} is false). Minted families:
 * ANF temps {@code t<digits>} and {@code __merge$<digits>}; FixedArray slots
 * {@code <name>__<digits>}, {@code __idx_<digits>}, {@code __val_<digits>};
 * stack-lowering slots {@code _codePart}, {@code __param_*},
 * {@code __shadowed_*}, {@code _pub_<digits>}; auto-injected parameters
 * {@code _changePKH}, {@code _changeAmount}, {@code _newAmount},
 * {@code _serialisedOutputs}, {@code _prevOutScript_<digits>}, and
 * {@code txPreimage} in a StatefulSmartContract. EC-optimizer names are
 * allocated collision-free (F-086) and are not reserved.
 */
public final class ReservedNames {

    private ReservedNames() {}

    /** The diagnostic, shared verbatim by all seven tiers (source and --ir). */
    public static String message(String name) {
        return "'" + name + "' is reserved for compiler-generated names and cannot be used as an identifier";
    }

    private static final List<Pattern> STACK_LOWERING = List.of(
        Pattern.compile("^_codePart$"),
        Pattern.compile("^__param_"),
        Pattern.compile("^__shadowed_"),
        Pattern.compile("^_pub_[0-9]+$")
    );

    private static final List<Pattern> ANF_BINDING = List.of(
        Pattern.compile("^t[0-9]+$"),
        Pattern.compile("^__merge\\$[0-9]+$")
    );

    private static final List<Pattern> SOURCE_ONLY = List.of(
        Pattern.compile("^.+__[0-9]+$"),
        Pattern.compile("^__idx_[0-9]+$"),
        Pattern.compile("^__val_[0-9]+$"),
        Pattern.compile("^_changePKH$"),
        Pattern.compile("^_changeAmount$"),
        Pattern.compile("^_newAmount$"),
        Pattern.compile("^_serialisedOutputs$"),
        Pattern.compile("^_prevOutScript_[0-9]+$")
    );

    private static boolean matchesAny(String name, List<Pattern> ps) {
        for (Pattern p : ps) {
            if (p.matcher(name).find()) return true;
        }
        return false;
    }

    /** True if a SOURCE program may not declare {@code name} (after name mapping). */
    public static boolean isReservedSourceName(String name, boolean stateful) {
        return matchesAny(name, STACK_LOWERING)
            || matchesAny(name, ANF_BINDING)
            || matchesAny(name, SOURCE_ONLY)
            || (stateful && "txPreimage".equals(name));
    }

    /**
     * {@code --ir} rule: every position refuses the stack-lowering families; a
     * declaration (property, method, parameter, loop variable, the name a
     * load_param / load_prop / update_prop addresses) also refuses the ANF
     * binding families.
     */
    public static boolean isReservedIrName(String name, boolean declaration) {
        return matchesAny(name, STACK_LOWERING)
            || (declaration && matchesAny(name, ANF_BINDING));
    }
}
