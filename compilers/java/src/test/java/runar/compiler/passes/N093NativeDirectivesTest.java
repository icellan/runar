package runar.compiler.passes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import runar.compiler.Cli;
import runar.compiler.canonical.Jcs;
import runar.compiler.frontend.ParserDispatch;
import runar.compiler.ir.anf.AnfMethod;
import runar.compiler.ir.anf.AnfProgram;
import runar.compiler.ir.ast.ContractNode;
import runar.compiler.ir.stack.StackProgram;

/**
 * N-093 (user decisions R37/R38) -- {@code @embedAlways} and {@code @sighash}
 * on the eight non-TS surfaces, each spelled as a native modifier that mirrors
 * the surface's readonly idiom (Java tier port of the TS reference test
 * packages/runar-compiler/src/__tests__/n093-native-directives.test.ts):
 *
 * <pre>
 *   .runar.sol   ByteString immutable embedAlways x;   function f(..) public sighash(SINGLE | FORKID)
 *   .runar.move  #[embed_always] x: T,                  #[sighash(SINGLE | FORKID)] public fun f
 *   .runar.go    runar:"readonly,embedAlways"            //runar:sighash SINGLE|FORKID above the func
 *   .runar.rs    #[embed_always]                         #[sighash(SINGLE | FORKID)] pub fn f
 *   .runar.py    x: EmbedAlways[T]                       {@literal @}public(sighash="SINGLE|FORKID")
 *   .runar.zig   x: runar.EmbedAlways(T)                 pub fn f(..) runar.Sighash("SINGLE|FORKID")
 *   .runar.rb    prop :x, T, embed_always: true          runar_sighash 'SINGLE|FORKID' before the def
 *   .runar.java  {@literal @}EmbedAlways                 {@literal @}Sighash("SINGLE|FORKID")
 * </pre>
 *
 * <p>What this proves (Java compiler tier): each surface's port of
 * examples/ts/compiler-directives/Directives and EmbedTags compiles, fold OFF
 * and fold ON, to the pinned TS-reference script hex, keeps deployTag in the
 * constructor slots, carries sigHashType 0x43 on spendSingle only (read from
 * the lowered ANF, so every pass between the parser and the ANF must carry the
 * field), and lowers to the same ANF (source locations stripped) as this
 * tier's own .runar.ts compile of the original; every malformed native
 * spelling is REFUSED with the shared diagnostics the .runar.ts comment
 * directive uses (non-public method, two spellings, malformed argument, bad
 * flag set, directive on the wrong member kind), never a silent fall-back to
 * ALL|FORKID or to DCE; a sighash (or Java {@code @EmbedAlways}) on a
 * constructor / init is refused; a COMMENT directive on a non-TS surface is
 * still refused (the surface parsers drop comments) and the message names the
 * native spelling.
 *
 * <p>What it does NOT prove: anything about the other six compiler tiers
 * (cross-tier byte parity is the conformance suite's job); on-chain behaviour
 * of the bytes; that the examples run natively in their host languages (the
 * example suites do that).
 */
class N093NativeDirectivesTest {

    private static final String DIRECTIVES_HEX = "76009c63750078a900887b7bac7767519d76a90088ac68";
    private static final String EMBED_TAGS_HEX = "57595b537a59a2695379a90088547a547aac777777";
    private static final int SINGLE_FORKID = 0x43;

    /** [extension, Directives path, EmbedTags path -- null for Java: FixedArray cannot be spelled there]. */
    private static final String[][] SURFACES = {
        {".runar.sol", "sol/compiler-directives/Directives.runar.sol", "sol/compiler-directives/EmbedTags.runar.sol"},
        {".runar.move", "move/compiler-directives/Directives.runar.move", "move/compiler-directives/EmbedTags.runar.move"},
        {".runar.go", "go/compiler-directives/Directives.runar.go", "go/compiler-directives/EmbedTags.runar.go"},
        {".runar.rs", "rust/compiler-directives/Directives.runar.rs", "rust/compiler-directives/EmbedTags.runar.rs"},
        {".runar.py", "python/compiler-directives/Directives.runar.py", "python/compiler-directives/EmbedTags.runar.py"},
        {".runar.zig", "zig/compiler-directives/Directives.runar.zig", "zig/compiler-directives/EmbedTags.runar.zig"},
        {".runar.rb", "ruby/compiler-directives/Directives.runar.rb", "ruby/compiler-directives/EmbedTags.runar.rb"},
        {".runar.java", "java/src/main/java/runar/examples/compiler-directives/Directives.runar.java", null},
    };

    private static Path examplesDir() {
        Path cwd = Paths.get("").toAbsolutePath();
        for (Path p = cwd; p != null; p = p.getParent()) {
            Path candidate = p.resolve("examples").resolve("ts").resolve("compiler-directives");
            if (Files.isDirectory(candidate)) return p.resolve("examples");
        }
        throw new IllegalStateException("examples/ directory not found above " + cwd);
    }

    private static String read(String rel) {
        try {
            return Files.readString(examplesDir().resolve(rel), StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static String directivesOf(String ext) {
        for (String[] s : SURFACES) {
            if (s[0].equals(ext)) return read(s[1]);
        }
        throw new IllegalArgumentException(ext);
    }

    /** One compile: script hex, constructor-slot names, the lowered ANF, and its location-free JSON. */
    private record Built(String hex, List<String> slotNames, AnfProgram anf, String anfJson) {
        Integer sighashOf(String method) {
            for (AnfMethod m : anf.methods()) {
                if (m.name().equals(method)) return m.sighashType();
            }
            throw new AssertionError("no method " + method);
        }
    }

    /** The production Cli pipeline (see PipelineTestSupport), keeping every intermediate the checks read. */
    private static Built build(String src, String file, boolean foldOn) throws Exception {
        ContractNode contract = PipelineTestSupport.parseValidated(src, file);
        Typecheck.run(contract);
        contract = ExpandFixedArrays.run(contract);
        AnfProgram anf = AnfLower.run(contract);
        anf = Cli.optimizeAnf(anf, !foldOn);
        StackProgram stack = Peephole.run(StackLower.run(anf));
        Emit.EmitResultFull full = Emit.runResultFull(stack);
        List<String> slots = new ArrayList<>();
        for (Emit.ConstructorSlot s : full.constructorSlots()) {
            slots.add(contract.constructor().params().get(s.paramIndex()).name());
        }
        return new Built(full.scriptHex(), slots, anf, stripSourceLocs(Jcs.stringify(anf)));
    }

    /** The ANF JSON without source locations (which name the surface file). */
    private static String stripSourceLocs(String json) {
        return json.replaceAll(",\"sourceLoc\":\\{[^{}]*\\}", "").replaceAll("\"sourceLoc\":\\{[^{}]*\\},?", "");
    }

    /** The diagnostic text a refused source produces (ParserDispatch joins a parser's errors with "; "). */
    private static String parseError(String src, String file) {
        ParserDispatch.ParseException ex = assertThrows(
            ParserDispatch.ParseException.class, () -> ParserDispatch.parse(src, file),
            file + " was accepted");
        return ex.getMessage();
    }

    /** Replace exactly one occurrence, so a stale needle fails loudly. */
    private static String swap(String src, String from, String to) {
        int first = src.indexOf(from);
        assertTrue(first >= 0 && src.indexOf(from, first + 1) < 0, "needle not found exactly once: " + from);
        return src.substring(0, first) + to + src.substring(first + from.length());
    }

    // ---- Positive: every surface matches the .runar.ts reference -----------

    static Stream<Arguments> surfacesBothFolds() {
        List<Arguments> out = new ArrayList<>();
        for (boolean foldOn : new boolean[] {false, true}) {
            for (String[] s : SURFACES) out.add(Arguments.of(s[0], s[1], s[2], foldOn));
        }
        return out.stream();
    }

    @ParameterizedTest(name = "{0} fold-on={3}")
    @MethodSource("surfacesBothFolds")
    void nativeDirectivesMatchTsReference(String ext, String directives, String embedTags, boolean foldOn)
        throws Exception {
        Built tsDir = build(read("ts/compiler-directives/Directives.runar.ts"), "Directives.runar.ts", foldOn);
        Built tsEmb = build(read("ts/compiler-directives/EmbedTags.runar.ts"), "EmbedTags.runar.ts", foldOn);
        assertEquals(DIRECTIVES_HEX, tsDir.hex(), ".runar.ts Directives drifted");
        assertEquals(EMBED_TAGS_HEX, tsEmb.hex(), ".runar.ts EmbedTags drifted");

        Built r = build(read(directives), "Directives" + ext, foldOn);
        assertEquals(DIRECTIVES_HEX, r.hex(), ext);
        assertTrue(r.slotNames().contains("deployTag"), ext + ": slots " + r.slotNames());
        assertEquals(Integer.valueOf(SINGLE_FORKID), r.sighashOf("spendSingle"), ext + ": spendSingle sigHashType");
        assertNull(r.sighashOf("spendAll"), ext + ": spendAll sigHashType");
        assertEquals(tsDir.anfJson(), r.anfJson(), ext + ": ANF differs from the .runar.ts original");
        if (embedTags != null) {
            Built e = build(read(embedTags), "EmbedTags" + ext, foldOn);
            assertEquals(EMBED_TAGS_HEX, e.hex(), ext + " EmbedTags");
        }
    }

    // ---- Negative: malformed native spellings are refused ------------------

    private static final String NON_PUBLIC = "@sighash directive on non-public method";
    private static final String MULTIPLE = "more than one @sighash directive on this method";
    private static final String MALFORMED = "@sighash: malformed directive";
    private static final String NO_FORKID = "FORKID is mandatory on BSV";
    private static final String LOST_SIGHASH = "@sighash directive is not attached to any method";
    private static final String LOST_EMBED = "@embedAlways directive is not attached to any property";

    /** [extension, label, from, to, expected error substring]. */
    static Stream<Arguments> negatives() {
        return Stream.of(
            Arguments.of(".runar.sol", "no FORKID", "sighash(SINGLE | FORKID)", "sighash(SINGLE)", NO_FORKID),
            Arguments.of(".runar.sol", "comma-separated", "sighash(SINGLE | FORKID)", "sighash(SINGLE, FORKID)", MALFORMED),
            Arguments.of(".runar.sol", "two modifiers", "sighash(SINGLE | FORKID)", "sighash(SINGLE | FORKID) sighash(ALL | FORKID)", MULTIPLE),
            Arguments.of(".runar.sol", "private method", "public sighash(SINGLE | FORKID)", "private sighash(SINGLE | FORKID)", NON_PUBLIC),
            Arguments.of(".runar.move", "no FORKID", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE)]", NO_FORKID),
            Arguments.of(".runar.move", "comma-separated", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE, FORKID)]", MALFORMED),
            Arguments.of(".runar.move", "two attributes", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", MULTIPLE),
            Arguments.of(".runar.move", "private fun", "public fun spend_single", "fun spend_single", NON_PUBLIC),
            Arguments.of(".runar.move", "sighash on a field", "#[embed_always]", "#[sighash(SINGLE | FORKID)]", LOST_SIGHASH),
            Arguments.of(".runar.move", "embed_always on a fun", "#[sighash(SINGLE | FORKID)]", "#[embed_always]", LOST_EMBED),
            Arguments.of(".runar.move", "unknown attribute", "#[sighash(SINGLE | FORKID)]", "#[test]", "unsupported Move attribute #[test]"),
            Arguments.of(".runar.go", "no FORKID", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE", NO_FORKID),
            Arguments.of(".runar.go", "comma-separated", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE,FORKID", MALFORMED),
            Arguments.of(".runar.go", "glued", "//runar:sighash SINGLE|FORKID", "//runar:sighashSINGLE|FORKID", "unknown Go DSL directive '//runar:sighashSINGLE|FORKID'"),
            Arguments.of(".runar.go", "two directives", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE|FORKID\n//runar:sighash ALL|FORKID", MULTIPLE),
            Arguments.of(".runar.go", "unexported method", "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) SpendSingle", "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) spendSingleHelper() {}\n\nfunc (c *Directives) SpendSingle", NON_PUBLIC),
            Arguments.of(".runar.go", "not above a func", "type Directives struct", "//runar:sighash SINGLE|FORKID\ntype Directives struct", LOST_SIGHASH),
            Arguments.of(".runar.go", "unknown directive", "//runar:sighash SINGLE|FORKID", "//runar:inline", "unknown Go DSL directive '//runar:inline'"),
            Arguments.of(".runar.rs", "no FORKID", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE)]", NO_FORKID),
            Arguments.of(".runar.rs", "comma-separated", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE, FORKID)]", MALFORMED),
            Arguments.of(".runar.rs", "two attributes", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", MULTIPLE),
            Arguments.of(".runar.rs", "private fn", "pub fn spend_single", "fn spend_single", NON_PUBLIC),
            Arguments.of(".runar.rs", "sighash on a field", "#[embed_always]", "#[sighash(SINGLE | FORKID)]", LOST_SIGHASH),
            Arguments.of(".runar.rs", "embed_always on a fn", "#[sighash(SINGLE | FORKID)]", "#[embed_always]", LOST_EMBED),
            Arguments.of(".runar.py", "no FORKID", "@public(sighash=\"SINGLE|FORKID\")", "@public(sighash=\"SINGLE\")", NO_FORKID),
            Arguments.of(".runar.py", "non-string argument", "@public(sighash=\"SINGLE|FORKID\")", "@public(sighash=SINGLE)", MALFORMED),
            Arguments.of(".runar.py", "bytes argument", "@public(sighash=\"SINGLE|FORKID\")", "@public(sighash=b'00')", MALFORMED),
            Arguments.of(".runar.py", "unknown keyword", "@public(sighash=\"SINGLE|FORKID\")", "@public(mode=\"SINGLE|FORKID\")", MALFORMED),
            Arguments.of(".runar.py", "two decorators", "@public(sighash=\"SINGLE|FORKID\")", "@public(sighash=\"SINGLE|FORKID\")\n    @public(sighash=\"ALL|FORKID\")", MULTIPLE),
            Arguments.of(".runar.zig", "no FORKID", "runar.Sighash(\"SINGLE|FORKID\")", "runar.Sighash(\"SINGLE\")", NO_FORKID),
            Arguments.of(".runar.zig", "non-string argument", "runar.Sighash(\"SINGLE|FORKID\")", "runar.Sighash(SINGLE)", MALFORMED),
            Arguments.of(".runar.zig", "private fn", "pub fn spendSingle", "fn spendSingle", NON_PUBLIC),
            Arguments.of(".runar.rb", "no FORKID", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE'", NO_FORKID),
            Arguments.of(".runar.rb", "symbol argument", "runar_sighash 'SINGLE|FORKID'", "runar_sighash :single", MALFORMED),
            Arguments.of(".runar.rb", "two macros", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE|FORKID'\n  runar_sighash 'ALL|FORKID'", MULTIPLE),
            Arguments.of(".runar.rb", "private method", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_sighash 'SINGLE|FORKID'\n", NON_PUBLIC),
            Arguments.of(".runar.rb", "no following def", "\nend\n", "\n\n  runar_sighash 'ALL|FORKID'\nend\n", LOST_SIGHASH),
            Arguments.of(".runar.java", "no FORKID", "@Sighash(\"SINGLE|FORKID\")", "@Sighash(\"SINGLE\")", NO_FORKID),
            Arguments.of(".runar.java", "non-string argument", "@Sighash(\"SINGLE|FORKID\")", "@Sighash(1)", MALFORMED),
            Arguments.of(".runar.java", "named value", "@Sighash(\"SINGLE|FORKID\")", "@Sighash(value = \"SINGLE|FORKID\")", MALFORMED),
            Arguments.of(".runar.java", "no argument", "@Sighash(\"SINGLE|FORKID\")", "@Sighash", MALFORMED),
            Arguments.of(".runar.java", "two annotations", "@Sighash(\"SINGLE|FORKID\")", "@Sighash(\"SINGLE|FORKID\")\n    @Sighash(\"ALL|FORKID\")", MULTIPLE),
            Arguments.of(".runar.java", "no @Public", "    @Public\n    @Sighash", "    @Sighash", NON_PUBLIC),
            Arguments.of(".runar.java", "@Sighash on a field", "@Readonly @EmbedAlways ByteString", "@Readonly @Sighash(\"ALL|FORKID\") ByteString", LOST_SIGHASH),
            Arguments.of(".runar.java", "@EmbedAlways on a method", "@Sighash(\"SINGLE|FORKID\")", "@EmbedAlways", LOST_EMBED)
        );
    }

    @ParameterizedTest(name = "{0}: {1}")
    @MethodSource("negatives")
    void malformedNativeSpellingRefused(String ext, String label, String from, String to, String want) {
        String err = parseError(swap(directivesOf(ext), from, to), "Directives" + ext);
        assertTrue(err.contains(want), ext + ": " + label + ": got " + err);
    }

    // ---- Composition with the readonly idiom --------------------------------

    /** [label, extension, from, to, check: hex | sighash | no_deploy_tag]. */
    static Stream<Arguments> compositions() {
        return Stream.of(
            Arguments.of("rs: #[embed_always] before #[readonly]", ".runar.rs", "#[readonly]\n    #[embed_always]", "#[embed_always]\n    #[readonly]", "hex"),
            Arguments.of("rs: #[runar::sighash(...)]", ".runar.rs", "#[sighash(", "#[runar::sighash(", "sighash"),
            Arguments.of("py: Readonly[EmbedAlways[T]]", ".runar.py", "EmbedAlways[ByteString]", "Readonly[EmbedAlways[ByteString]]", "hex"),
            Arguments.of("zig: runar.Readonly(runar.EmbedAlways(T))", ".runar.zig", "runar.EmbedAlways(runar.ByteString)", "runar.Readonly(runar.EmbedAlways(runar.ByteString))", "hex"),
            Arguments.of("sol: embedAlways before immutable", ".runar.sol", "ByteString immutable embedAlways deployTag", "ByteString embedAlways immutable deployTag", "hex"),
            Arguments.of("rb: runar_sighash after runar_public", ".runar.rb", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_public sig: Sig, pub_key: PubKey\n  runar_sighash 'SINGLE|FORKID'\n", "sighash"),
            Arguments.of("go: doc comment between directive and func", ".runar.go", "//runar:sighash SINGLE|FORKID\n", "//runar:sighash SINGLE|FORKID\n// SpendSingle commits to one output.\n", "sighash"),
            Arguments.of("go: tag without embedAlways is not embedded", ".runar.go", "`runar:\"readonly,embedAlways\"`", "`runar:\"readonly\"`", "no_deploy_tag"),
            Arguments.of("java: @EmbedAlways before @Readonly", ".runar.java", "@Readonly @EmbedAlways ByteString", "@EmbedAlways @Readonly ByteString", "hex")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("compositions")
    void nativeSpellingsComposeWithReadonly(String label, String ext, String from, String to, String check)
        throws Exception {
        Built r = build(swap(directivesOf(ext), from, to), "Directives" + ext, false);
        switch (check) {
            case "hex" -> assertEquals(DIRECTIVES_HEX, r.hex(), label);
            case "sighash" -> assertEquals(Integer.valueOf(SINGLE_FORKID), r.sighashOf("spendSingle"), label);
            default -> assertFalse(r.slotNames().contains("deployTag"), label);
        }
    }

    // ---- The comment-form guard names the native spelling -------------------

    static Stream<Arguments> commentNames() {
        return Stream.of(
            Arguments.of(".runar.sol", "Solidity", "solidity", "the function modifier sighash(<FLAGS>)", "the property modifier embedAlways"),
            Arguments.of(".runar.move", "Move", "move", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
            Arguments.of(".runar.go", "Go DSL", "go", "the directive //runar:sighash <FLAGS>", "the struct tag option runar:\"readonly,embedAlways\""),
            Arguments.of(".runar.rs", "Rust", "rust", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"),
            Arguments.of(".runar.py", "Python", "python", "@public(sighash=\"<FLAGS>\")", "the wrapper type EmbedAlways[T]"),
            Arguments.of(".runar.zig", "Zig", "zig", "the return type runar.Sighash(\"<FLAGS>\")", "the type function runar.EmbedAlways(T)"),
            Arguments.of(".runar.rb", "Ruby", "ruby", "runar_sighash '<FLAGS>'", "the prop option embed_always: true"),
            Arguments.of(".runar.java", "Java", "java", "the annotation @Sighash(\"<FLAGS>\")", "the annotation @EmbedAlways")
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("commentNames")
    void commentDirectiveOnNonTsSurfaceNamesNativeSpelling(String ext, String surface, String doc, String sig, String emb) {
        String src = directivesOf(ext);
        String comment = ext.equals(".runar.py") || ext.equals(".runar.rb") ? "#" : "//";
        String file = "Directives" + ext;
        assertEquals(
            "@sighash directive (issue #123) is not supported as a comment by the " + surface
                + " surface parser; write it as " + sig + " (see docs/formats/" + doc + ".md)",
            parseError(comment + " @sighash SINGLE|FORKID\n" + src, file));
        assertEquals(
            "@embedAlways directive (issue #109) is not supported as a comment by the " + surface
                + " surface parser; write it as " + emb + " (see docs/formats/" + doc + ".md)",
            parseError(comment + " @embedAlways\n" + src, file));
    }

    // ---- Constructor / init carries no directive ----------------------------

    /**
     * The constructor / init cases the TS reference refuses with
     * lostDirectiveMessage: a constructor is neither a spending entry point
     * nor a field, so a sighash (or Java @EmbedAlways) on it would be dropped
     * silently.
     */
    static Stream<Arguments> constructorCases() {
        return Stream.of(
            Arguments.of(".runar.rs", "    pub fn spend_all", "    #[sighash(ALL | FORKID)]\n    pub fn init(&mut self) {}\n\n    pub fn spend_all", LOST_SIGHASH),
            Arguments.of(".runar.zig", ", deployTag: runar.ByteString) Directives {", ", deployTag: runar.ByteString) runar.Sighash(\"ALL|FORKID\") {", LOST_SIGHASH),
            Arguments.of(".runar.py", "    def __init__", "    @public(sighash=\"ALL|FORKID\")\n    def __init__", LOST_SIGHASH),
            Arguments.of(".runar.rb", "  def initialize", "  runar_sighash 'ALL|FORKID'\n  def initialize", LOST_SIGHASH),
            Arguments.of(".runar.java", "    Directives(Addr", "    @Sighash(\"ALL|FORKID\")\n    Directives(Addr", LOST_SIGHASH),
            Arguments.of(".runar.java", "    Directives(Addr", "    @EmbedAlways\n    Directives(Addr", LOST_EMBED)
        );
    }

    @ParameterizedTest(name = "{0}: {3}")
    @MethodSource("constructorCases")
    void directiveOnConstructorRefused(String ext, String from, String to, String want) {
        String err = parseError(swap(directivesOf(ext), from, to), "Directives" + ext);
        assertTrue(err.contains(want), ext + ": got " + err);
    }
}
