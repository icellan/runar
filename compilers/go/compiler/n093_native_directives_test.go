package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/icellan/runar/compilers/go/frontend"
)

// N-093 (user decisions R37/R38) — `@embedAlways` and `@sighash` on the eight
// non-TS surfaces, each spelled as a native modifier that mirrors the
// surface's readonly idiom (Go tier port of the TS reference test
// packages/runar-compiler/src/__tests__/n093-native-directives.test.ts):
//
//	.runar.sol   `ByteString immutable embedAlways x;`   `function f(..) public sighash(SINGLE | FORKID)`
//	.runar.move  `#[embed_always] x: T,`                  `#[sighash(SINGLE | FORKID)] public fun f`
//	.runar.go    `runar:"readonly,embedAlways"`            `//runar:sighash SINGLE|FORKID` above the func
//	.runar.rs    `#[embed_always]`                         `#[sighash(SINGLE | FORKID)] pub fn f`
//	.runar.py    `x: EmbedAlways[T]`                       `@public(sighash="SINGLE|FORKID")`
//	.runar.zig   `x: runar.EmbedAlways(T)`                 `pub fn f(..) runar.Sighash("SINGLE|FORKID")`
//	.runar.rb    `prop :x, T, embed_always: true`          `runar_sighash 'SINGLE|FORKID'` before the def
//	.runar.java  `@EmbedAlways`                            `@Sighash("SINGLE|FORKID")`
//
// What this proves (Go compiler tier):
//   - each surface's port of examples/ts/compiler-directives/Directives and
//     EmbedTags compiles, fold OFF and fold ON, to the pinned TS-reference
//     script hex, keeps deployTag in constructorSlots, carries sigHashType
//     0x43 on spendSingle only, and lowers to the same ANF (source locations
//     stripped) as the Go tier's own .runar.ts compile of the original;
//   - every malformed native spelling is REFUSED with the shared diagnostics
//     the .runar.ts comment directive uses (non-public method, two spellings,
//     malformed argument, bad flag set, directive on the wrong member kind),
//     never a silent fall-back to ALL|FORKID or to DCE;
//   - a COMMENT directive on a non-TS surface is still refused (the surface
//     parsers drop comments) and the message names the native spelling.
//
// What it does NOT prove:
//   - anything about the other six compiler tiers (each has its own port;
//     cross-tier byte parity is the conformance suite's job);
//   - on-chain behaviour of the bytes (the real-crypto witnesses do that);
//   - that the examples build natively in their host languages (the example
//     suites do that).

const (
	n093DirectivesHex = "76009c63750078a900887b7bac7767519d76a90088ac68"
	n093EmbedTagsHex  = "57595b537a59a2695379a90088547a547aac777777"
	n093SingleForkID  = 0x43
)

func n093Examples() string {
	return filepath.Join("..", "..", "..", "examples")
}

func n093Read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(n093Examples(), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

type n093Surface struct {
	ext        string
	directives string // path under examples/
	embedTags  string // "" for Java (FixedArray cannot be spelled there)
}

var n093Surfaces = []n093Surface{
	{".runar.sol", "sol/compiler-directives/Directives.runar.sol", "sol/compiler-directives/EmbedTags.runar.sol"},
	{".runar.move", "move/compiler-directives/Directives.runar.move", "move/compiler-directives/EmbedTags.runar.move"},
	{".runar.go", "go/compiler-directives/Directives.runar.go", "go/compiler-directives/EmbedTags.runar.go"},
	{".runar.rs", "rust/compiler-directives/Directives.runar.rs", "rust/compiler-directives/EmbedTags.runar.rs"},
	{".runar.py", "python/compiler-directives/Directives.runar.py", "python/compiler-directives/EmbedTags.runar.py"},
	{".runar.zig", "zig/compiler-directives/Directives.runar.zig", "zig/compiler-directives/EmbedTags.runar.zig"},
	{".runar.rb", "ruby/compiler-directives/Directives.runar.rb", "ruby/compiler-directives/EmbedTags.runar.rb"},
	{".runar.java", "java/src/main/java/runar/examples/compiler-directives/Directives.runar.java", ""},
}

func n093Surf(ext string) n093Surface {
	for _, s := range n093Surfaces {
		if s.ext == ext {
			return s
		}
	}
	panic("unknown surface " + ext)
}

func n093Build(t *testing.T, src, fileName string, foldOn bool) *CompileResult {
	t.Helper()
	r := CompileFromSourceStrWithResult(src, fileName, CompileOptions{DisableConstantFolding: !foldOn})
	if !r.Success {
		t.Fatalf("%s (foldOn=%v) did not compile: %v", fileName, foldOn, diagMessages(r))
	}
	return r
}

// n093CanonicalANF is the ANF IR as JSON without source locations (which name
// the surface file).
func n093CanonicalANF(t *testing.T, r *CompileResult) string {
	t.Helper()
	raw, err := json.Marshal(r.ANF)
	if err != nil {
		t.Fatalf("marshal ANF: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal ANF: %v", err)
	}
	var strip func(interface{}) interface{}
	strip = func(x interface{}) interface{} {
		switch n := x.(type) {
		case map[string]interface{}:
			delete(n, "sourceLoc")
			for k, c := range n {
				n[k] = strip(c)
			}
		case []interface{}:
			for i, c := range n {
				n[i] = strip(c)
			}
		}
		return x
	}
	out, _ := json.Marshal(strip(v))
	return string(out)
}

func n093SigHash(r *CompileResult) map[string]*int {
	m := map[string]*int{}
	for _, meth := range r.Artifact.ABI.Methods {
		m[meth.Name] = meth.SigHashType
	}
	return m
}

func n093Errors(src, fileName string) []string {
	res := frontend.ParseSource([]byte(src), fileName)
	var out []string
	for _, d := range res.Errors {
		if d.Severity == frontend.SeverityError {
			out = append(out, d.Message)
		}
	}
	return out
}

// n093Swap replaces exactly one occurrence, so a stale needle fails loudly.
func n093Swap(t *testing.T, src, from, to string) string {
	t.Helper()
	if n := strings.Count(src, from); n != 1 {
		t.Fatalf("needle found %d times (want exactly 1): %q", n, from)
	}
	return strings.Replace(src, from, to, 1)
}

func TestN093_NativeDirectives_MatchTSReference(t *testing.T) {
	for _, foldOn := range []bool{false, true} {
		tsDir := n093Build(t, n093Read(t, "ts/compiler-directives/Directives.runar.ts"), "Directives.runar.ts", foldOn)
		tsEmb := n093Build(t, n093Read(t, "ts/compiler-directives/EmbedTags.runar.ts"), "EmbedTags.runar.ts", foldOn)
		if tsDir.ScriptHex != n093DirectivesHex || tsEmb.ScriptHex != n093EmbedTagsHex {
			t.Fatalf("foldOn=%v: .runar.ts reference drifted: %s / %s", foldOn, tsDir.ScriptHex, tsEmb.ScriptHex)
		}
		tsANF := n093CanonicalANF(t, tsDir)
		for _, s := range n093Surfaces {
			s := s
			t.Run(s.ext+"/fold="+map[bool]string{false: "off", true: "on"}[foldOn], func(t *testing.T) {
				r := n093Build(t, n093Read(t, s.directives), "Directives"+s.ext, foldOn)
				if r.ScriptHex != n093DirectivesHex {
					t.Errorf("Directives hex: got %s want %s", r.ScriptHex, n093DirectivesHex)
				}
				if !contains(slotNames(r), "deployTag") {
					t.Errorf("deployTag missing from constructor slots: %v", slotNames(r))
				}
				sh := n093SigHash(r)
				if v := sh["spendSingle"]; v == nil || *v != n093SingleForkID {
					t.Errorf("spendSingle sigHashType: got %v want 0x43", v)
				}
				if v := sh["spendAll"]; v != nil {
					t.Errorf("spendAll sigHashType: got %d want absent", *v)
				}
				if got := n093CanonicalANF(t, r); got != tsANF {
					t.Errorf("ANF differs from the .runar.ts original:\n got %s\nwant %s", got, tsANF)
				}
				if s.embedTags != "" {
					e := n093Build(t, n093Read(t, s.embedTags), "EmbedTags"+s.ext, foldOn)
					if e.ScriptHex != n093EmbedTagsHex {
						t.Errorf("EmbedTags hex: got %s want %s", e.ScriptHex, n093EmbedTagsHex)
					}
				}
			})
		}
	}
}

const (
	n093NonPublic   = "@sighash directive on non-public method"
	n093Multiple    = "more than one @sighash directive on this method"
	n093Malformed   = "@sighash: malformed directive"
	n093NoForkID    = "FORKID is mandatory on BSV"
	n093LostSighash = "@sighash directive is not attached to any method"
	n093LostEmbed   = "@embedAlways directive is not attached to any property"
)

type n093Case struct {
	label, from, to, want string
}

var n093Negatives = map[string][]n093Case{
	".runar.sol": {
		{"no FORKID", "sighash(SINGLE | FORKID)", "sighash(SINGLE)", n093NoForkID},
		{"comma-separated", "sighash(SINGLE | FORKID)", "sighash(SINGLE, FORKID)", n093Malformed},
		{"two modifiers", "sighash(SINGLE | FORKID)", "sighash(SINGLE | FORKID) sighash(ALL | FORKID)", n093Multiple},
		{"private method", "public sighash(SINGLE | FORKID)", "private sighash(SINGLE | FORKID)", n093NonPublic},
	},
	".runar.move": {
		{"no FORKID", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE)]", n093NoForkID},
		{"comma-separated", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE, FORKID)]", n093Malformed},
		{"two attributes", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", n093Multiple},
		{"private fun", "public fun spend_single", "fun spend_single", n093NonPublic},
		{"sighash on a field", "#[embed_always]", "#[sighash(SINGLE | FORKID)]", n093LostSighash},
		{"embed_always on a fun", "#[sighash(SINGLE | FORKID)]", "#[embed_always]", n093LostEmbed},
		{"unknown attribute", "#[sighash(SINGLE | FORKID)]", "#[test]", "unsupported Move attribute #[test]"},
	},
	".runar.go": {
		{"no FORKID", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE", n093NoForkID},
		{"comma-separated", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE,FORKID", n093Malformed},
		{"glued", "//runar:sighash SINGLE|FORKID", "//runar:sighashSINGLE|FORKID", "unknown Go DSL directive '//runar:sighashSINGLE|FORKID'"},
		{"two directives", "//runar:sighash SINGLE|FORKID", "//runar:sighash SINGLE|FORKID\n//runar:sighash ALL|FORKID", n093Multiple},
		{"unexported method", "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) SpendSingle", "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) spendSingleHelper() {}\n\nfunc (c *Directives) SpendSingle", n093NonPublic},
		{"not above a func", "type Directives struct", "//runar:sighash SINGLE|FORKID\ntype Directives struct", n093LostSighash},
		{"unknown directive", "//runar:sighash SINGLE|FORKID", "//runar:inline", "unknown Go DSL directive '//runar:inline'"},
	},
	".runar.rs": {
		{"no FORKID", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE)]", n093NoForkID},
		{"comma-separated", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE, FORKID)]", n093Malformed},
		{"two attributes", "#[sighash(SINGLE | FORKID)]", "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", n093Multiple},
		{"private fn", "pub fn spend_single", "fn spend_single", n093NonPublic},
		{"sighash on a field", "#[embed_always]", "#[sighash(SINGLE | FORKID)]", n093LostSighash},
		{"embed_always on a fn", "#[sighash(SINGLE | FORKID)]", "#[embed_always]", n093LostEmbed},
	},
	".runar.py": {
		{"no FORKID", `@public(sighash="SINGLE|FORKID")`, `@public(sighash="SINGLE")`, n093NoForkID},
		{"non-string argument", `@public(sighash="SINGLE|FORKID")`, `@public(sighash=SINGLE)`, n093Malformed},
		{"unknown keyword", `@public(sighash="SINGLE|FORKID")`, `@public(mode="SINGLE|FORKID")`, n093Malformed},
		{"two decorators", `@public(sighash="SINGLE|FORKID")`, "@public(sighash=\"SINGLE|FORKID\")\n    @public(sighash=\"ALL|FORKID\")", n093Multiple},
	},
	".runar.zig": {
		{"no FORKID", `runar.Sighash("SINGLE|FORKID")`, `runar.Sighash("SINGLE")`, n093NoForkID},
		{"non-string argument", `runar.Sighash("SINGLE|FORKID")`, `runar.Sighash(SINGLE)`, n093Malformed},
		{"private fn", "pub fn spendSingle", "fn spendSingle", n093NonPublic},
	},
	".runar.rb": {
		{"no FORKID", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE'", n093NoForkID},
		{"symbol argument", "runar_sighash 'SINGLE|FORKID'", "runar_sighash :single", n093Malformed},
		{"two macros", "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE|FORKID'\n  runar_sighash 'ALL|FORKID'", n093Multiple},
		{"private method", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_sighash 'SINGLE|FORKID'\n", n093NonPublic},
		{"no following def", "\nend\n", "\n\n  runar_sighash 'ALL|FORKID'\nend\n", n093LostSighash},
	},
	".runar.java": {
		{"no FORKID", `@Sighash("SINGLE|FORKID")`, `@Sighash("SINGLE")`, n093NoForkID},
		{"non-string argument", `@Sighash("SINGLE|FORKID")`, `@Sighash(1)`, n093Malformed},
		{"two annotations", `@Sighash("SINGLE|FORKID")`, "@Sighash(\"SINGLE|FORKID\")\n    @Sighash(\"ALL|FORKID\")", n093Multiple},
		{"no @Public", "    @Public\n    @Sighash", "    @Sighash", n093NonPublic},
		{"@Sighash on a field", "@Readonly @EmbedAlways ByteString", `@Readonly @Sighash("ALL|FORKID") ByteString`, n093LostSighash},
		{"@EmbedAlways on a method", `@Sighash("SINGLE|FORKID")`, "@EmbedAlways", n093LostEmbed},
	},
}

func TestN093_MalformedNativeSpellingRefused(t *testing.T) {
	for _, s := range n093Surfaces {
		src := n093Read(t, s.directives)
		for _, c := range n093Negatives[s.ext] {
			c := c
			t.Run(s.ext+"/"+c.label, func(t *testing.T) {
				errs := n093Errors(n093Swap(t, src, c.from, c.to), "Directives"+s.ext)
				if !strings.Contains(strings.Join(errs, "\n"), c.want) {
					t.Fatalf("want an error containing %q, got %q", c.want, errs)
				}
			})
		}
	}
}

func TestN093_NativeSpellingsComposeWithReadonly(t *testing.T) {
	type comp struct {
		label, ext, from, to string
		check                string // "hex" | "sighash" | "noDeployTag"
	}
	cases := []comp{
		{"rs: #[embed_always] before #[readonly]", ".runar.rs", "#[readonly]\n    #[embed_always]", "#[embed_always]\n    #[readonly]", "hex"},
		{"rs: #[runar::sighash(...)]", ".runar.rs", "#[sighash(", "#[runar::sighash(", "sighash"},
		{"py: Readonly[EmbedAlways[T]]", ".runar.py", "EmbedAlways[ByteString]", "Readonly[EmbedAlways[ByteString]]", "hex"},
		{"zig: runar.Readonly(runar.EmbedAlways(T))", ".runar.zig", "runar.EmbedAlways(runar.ByteString)", "runar.Readonly(runar.EmbedAlways(runar.ByteString))", "hex"},
		{"sol: embedAlways before immutable", ".runar.sol", "ByteString immutable embedAlways deployTag", "ByteString embedAlways immutable deployTag", "hex"},
		{"rb: runar_sighash after runar_public", ".runar.rb", "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_public sig: Sig, pub_key: PubKey\n  runar_sighash 'SINGLE|FORKID'\n", "sighash"},
		{"go: doc comment between directive and func", ".runar.go", "//runar:sighash SINGLE|FORKID\n", "//runar:sighash SINGLE|FORKID\n// SpendSingle commits to one output.\n", "sighash"},
		{"go: tag without embedAlways is not embedded", ".runar.go", "`runar:\"readonly,embedAlways\"`", "`runar:\"readonly\"`", "noDeployTag"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.label, func(t *testing.T) {
			src := n093Swap(t, n093Read(t, n093Surf(c.ext).directives), c.from, c.to)
			r := n093Build(t, src, "Directives"+c.ext, false)
			switch c.check {
			case "hex":
				if r.ScriptHex != n093DirectivesHex {
					t.Fatalf("hex: got %s want %s", r.ScriptHex, n093DirectivesHex)
				}
			case "sighash":
				if v := n093SigHash(r)["spendSingle"]; v == nil || *v != n093SingleForkID {
					t.Fatalf("spendSingle sigHashType: got %v want 0x43", v)
				}
			case "noDeployTag":
				if contains(slotNames(r), "deployTag") {
					t.Fatalf("deployTag should be eliminated: %v", slotNames(r))
				}
			}
		})
	}
}

func TestN093_CommentDirectiveOnNonTSSurfaceNamesNativeSpelling(t *testing.T) {
	names := map[string][4]string{
		".runar.sol":  {"Solidity", "solidity", "the function modifier sighash(<FLAGS>)", "the property modifier embedAlways"},
		".runar.move": {"Move", "move", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"},
		".runar.go":   {"Go DSL", "go", "the directive //runar:sighash <FLAGS>", `the struct tag option runar:"readonly,embedAlways"`},
		".runar.rs":   {"Rust", "rust", "the attribute #[sighash(<FLAGS>)]", "the attribute #[embed_always]"},
		".runar.py":   {"Python", "python", `@public(sighash="<FLAGS>")`, "the wrapper type EmbedAlways[T]"},
		".runar.zig":  {"Zig", "zig", `the return type runar.Sighash("<FLAGS>")`, "the type function runar.EmbedAlways(T)"},
		".runar.rb":   {"Ruby", "ruby", "runar_sighash '<FLAGS>'", "the prop option embed_always: true"},
		".runar.java": {"Java", "java", `the annotation @Sighash("<FLAGS>")`, "the annotation @EmbedAlways"},
	}
	for _, s := range n093Surfaces {
		n := names[s.ext]
		src := n093Read(t, s.directives)
		comment := "//"
		if s.ext == ".runar.py" || s.ext == ".runar.rb" {
			comment = "#"
		}
		t.Run(s.ext+"/@sighash comment", func(t *testing.T) {
			errs := n093Errors(comment+" @sighash SINGLE|FORKID\n"+src, "Directives"+s.ext)
			want := "@sighash directive (issue #123) is not supported as a comment by the " + n[0] + " surface parser; write it as " + n[2] + " (see docs/formats/" + n[1] + ".md)"
			if len(errs) != 1 || errs[0] != want {
				t.Fatalf("got %q\nwant [%q]", errs, want)
			}
		})
		t.Run(s.ext+"/@embedAlways comment", func(t *testing.T) {
			errs := n093Errors(comment+" @embedAlways\n"+src, "Directives"+s.ext)
			want := "@embedAlways directive (issue #109) is not supported as a comment by the " + n[0] + " surface parser; write it as " + n[3] + " (see docs/formats/" + n[1] + ".md)"
			if len(errs) != 1 || errs[0] != want {
				t.Fatalf("got %q\nwant [%q]", errs, want)
			}
		})
	}
}

// The constructor / init cases the TS reference refuses with
// lostDirectiveMessage: a constructor is neither a spending entry point nor a
// field, so a sighash (or Java @EmbedAlways) on it would be dropped silently.
func TestN093_DirectiveOnConstructorRefused(t *testing.T) {
	cases := []n093Case{
		{".runar.rs", "    pub fn spend_all", "    #[sighash(ALL | FORKID)]\n    pub fn init(&mut self) {}\n\n    pub fn spend_all", n093LostSighash},
		{".runar.zig", ", deployTag: runar.ByteString) Directives {", `, deployTag: runar.ByteString) runar.Sighash("ALL|FORKID") {`, n093LostSighash},
		{".runar.py", "    def __init__", "    @public(sighash=\"ALL|FORKID\")\n    def __init__", n093LostSighash},
		{".runar.rb", "  def initialize", "  runar_sighash 'ALL|FORKID'\n  def initialize", n093LostSighash},
		{".runar.java", "    Directives(Addr", "    @Sighash(\"ALL|FORKID\")\n    Directives(Addr", n093LostSighash},
		{".runar.java", "    Directives(Addr", "    @EmbedAlways\n    Directives(Addr", n093LostEmbed},
	}
	for _, c := range cases {
		c := c
		ext := c.label
		t.Run(ext+"/"+c.want, func(t *testing.T) {
			src := n093Swap(t, n093Read(t, n093Surf(ext).directives), c.from, c.to)
			errs := n093Errors(src, "Directives"+ext)
			if !strings.Contains(strings.Join(errs, "\n"), c.want) {
				t.Fatalf("want an error containing %q, got %q", c.want, errs)
			}
		})
	}
}
