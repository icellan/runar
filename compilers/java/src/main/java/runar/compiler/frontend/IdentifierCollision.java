package runar.compiler.frontend;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * F-017 — the identifier-collision rule.
 *
 * <p>Five surfaces rename identifiers on the way into the AST: {@code .runar.py},
 * {@code .runar.rb}, {@code .runar.rs}, {@code .runar.move} (snake_case to
 * camelCase) and {@code .runar.go} (PascalCase to camelCase). None of those
 * mappings is injective: {@code tmp} and {@code tmp_}, {@code a_b} and
 * {@code aB}, {@code _tmp} and {@code tmp} (.py/.rb), {@code Tmp} and
 * {@code tmp} (.go) each land on one Rúnar name. Before this rule both
 * spellings were bound to ONE variable, so
 * {@code tmp = n + 1; tmp_ = n + 2; assert_(tmp == tmp_)} — always false in
 * the source language — compiled to a self-comparison that always passes.
 *
 * <p>While parsing one contract, the surface parser records (source spelling,
 * Rúnar name) for every identifier it DECLARES: properties / struct fields,
 * method names (not the constructor), parameters (not receivers), locals at
 * every declaration or bare-name assignment target, and loop variables. If two
 * recorded pairs share a Rúnar name but differ in spelling, the contract is
 * refused with exactly one error whose text is identical in all seven tiers.
 * Mirrors {@code identifierCollisionMessage} in
 * packages/runar-compiler/src/passes/snake-to-camel.ts.
 */
final class IdentifierCollision {

    /** The (source spelling, Rúnar name) pairs declared by one contract. */
    static final class Declared {
        private final List<String[]> decls = new ArrayList<>();

        /** Record one declared identifier and return its Rúnar name. */
        String declare(String raw, String name) {
            decls.add(new String[] {raw, name});
            return name;
        }

        /** The single F-017 error message, or {@code null}. */
        String message() {
            return IdentifierCollision.message(decls);
        }
    }

    private IdentifierCollision() {}

    /**
     * The collision with the smallest Rúnar name and, for it, the two smallest
     * source spellings (ordinal order; identifiers here are ASCII), so the
     * report does not depend on declaration order. {@code null} when every
     * name has one spelling.
     */
    static String message(List<String[]> decls) {
        Map<String, TreeSet<String>> spellings = new TreeMap<>();
        for (String[] d : decls) {
            spellings.computeIfAbsent(d[1], k -> new TreeSet<>()).add(d[0]);
        }
        for (Map.Entry<String, TreeSet<String>> e : spellings.entrySet()) {
            if (e.getValue().size() >= 2) {
                var it = e.getValue().iterator();
                String a = it.next();
                String b = it.next();
                return "identifier collision: '" + a + "' and '" + b + "' both convert to '"
                    + e.getKey() + "'; rename one of them";
            }
        }
        return null;
    }
}
