// N-108 — the `Sha256Digest` alias on the Java surface.
//
// `docs/formats/java.md` documents `Sha256Digest -> Sha256` in the Java surface
// type table, and five of the seven tiers implemented it. The two that did not
// were Zig (`compilers/zig/src/passes/parse_java.zig`) and — the one that makes
// this a documentation bug as well as a parity bug — the JAVA TIER ITSELF
// (`compilers/java/.../frontend/JavaParser.java`), which refused the exact
// spelling its own format guide publishes.
//
// Kept as a `.runar.java` file rather than folded into the `.runar.ts` fixture
// because the alias is resolved per surface parser; a `.runar.ts` fixture
// exercises exactly one of the nine tables that have to agree.
package runar.examples.aliasjava;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.types.Sha256Digest;

import static runar.lang.Builtins.assertThat;

class Sha256DigestAliasJava extends StatefulSmartContract {

    Sha256Digest currentHash;

    Sha256DigestAliasJava(Sha256Digest currentHash) {
        super(currentHash);
        this.currentHash = currentHash;
    }

    @Public
    void update(Sha256Digest newHash) {
        this.currentHash = newHash;
        assertThat(true);
    }
}
