# frozen_string_literal: true

require 'tmpdir'
require_relative 'test_helper'

# N-093 (user decisions R37/R38) -- `@embedAlways` and `@sighash` on the eight
# non-TS surfaces, each spelled as a native modifier that mirrors the surface's
# readonly idiom (Ruby tier port of the TS reference test
# packages/runar-compiler/src/__tests__/n093-native-directives.test.ts):
#
#   .runar.sol   `ByteString immutable embedAlways x;`   `function f(..) public sighash(SINGLE | FORKID)`
#   .runar.move  `#[embed_always] x: T,`                  `#[sighash(SINGLE | FORKID)] public fun f`
#   .runar.go    `runar:"readonly,embedAlways"`            `//runar:sighash SINGLE|FORKID` above the func
#   .runar.rs    `#[embed_always]`                         `#[sighash(SINGLE | FORKID)] pub fn f`
#   .runar.py    `x: EmbedAlways[T]`                       `@public(sighash="SINGLE|FORKID")`
#   .runar.zig   `x: runar.EmbedAlways(T)`                 `pub fn f(..) runar.Sighash("SINGLE|FORKID")`
#   .runar.rb    `prop :x, T, embed_always: true`          `runar_sighash 'SINGLE|FORKID'` before the def
#   .runar.java  `@EmbedAlways`                            `@Sighash("SINGLE|FORKID")`
#
# What this proves (Ruby compiler tier):
#   - each surface's port of examples/ts/compiler-directives/Directives and
#     EmbedTags compiles, fold OFF and fold ON, to the pinned TS-reference
#     script hex, keeps deployTag in the constructor slots, carries
#     sigHashType 0x43 on spendSingle only, and lowers to the same ANF (source
#     locations stripped) as this tier's own .runar.ts compile of the original;
#   - every malformed native spelling is REFUSED with the shared diagnostics
#     the .runar.ts comment directive uses (non-public method, two spellings,
#     malformed argument, bad flag set, directive on the wrong member kind),
#     never a silent fall-back to ALL|FORKID or to DCE;
#   - a sighash (or Java @EmbedAlways) on a constructor / init is refused;
#   - a COMMENT directive on a non-TS surface is still refused (the surface
#     parsers drop comments) and the message names the native spelling.
#
# What it does NOT prove:
#   - anything about the other six compiler tiers (each has its own port;
#     cross-tier byte parity is the conformance suite's job);
#   - on-chain behaviour of the bytes (the real-crypto witnesses do that);
#   - that the examples run natively in their host languages (the example
#     suites do that).
class TestN093NativeDirectives < Minitest::Test
  EXAMPLES = File.expand_path('../../../examples', __dir__)

  DIRECTIVES_HEX = '76009c63750078a900887b7bac7767519d76a90088ac68'
  EMBED_TAGS_HEX = '57595b537a59a2695379a90088547a547aac777777'
  SINGLE_FORKID = 0x43

  # [extension, Directives path, EmbedTags path -- nil for Java: FixedArray
  # cannot be spelled there].
  SURFACES = [
    ['.runar.sol', 'sol/compiler-directives/Directives.runar.sol', 'sol/compiler-directives/EmbedTags.runar.sol'],
    ['.runar.move', 'move/compiler-directives/Directives.runar.move', 'move/compiler-directives/EmbedTags.runar.move'],
    ['.runar.go', 'go/compiler-directives/Directives.runar.go', 'go/compiler-directives/EmbedTags.runar.go'],
    ['.runar.rs', 'rust/compiler-directives/Directives.runar.rs', 'rust/compiler-directives/EmbedTags.runar.rs'],
    ['.runar.py', 'python/compiler-directives/Directives.runar.py', 'python/compiler-directives/EmbedTags.runar.py'],
    ['.runar.zig', 'zig/compiler-directives/Directives.runar.zig', 'zig/compiler-directives/EmbedTags.runar.zig'],
    ['.runar.rb', 'ruby/compiler-directives/Directives.runar.rb', 'ruby/compiler-directives/EmbedTags.runar.rb'],
    ['.runar.java', 'java/src/main/java/runar/examples/compiler-directives/Directives.runar.java', nil],
  ].freeze

  def self.read(rel)
    File.read(File.join(EXAMPLES, rel), encoding: 'UTF-8')
  end

  def self.directives_of(ext)
    read(SURFACES.find { |s| s[0] == ext }[1])
  end

  def self.slug(text)
    text.gsub(/[^A-Za-z0-9]+/, '_').downcase
  end

  # Compile +src+ as file +file_name+ (the extension selects the parser).
  def build(src, file_name, fold_on)
    Dir.mktmpdir do |dir|
      path = File.join(dir, file_name)
      File.write(path, src)
      artifact = RunarCompiler.compile_from_source(path, disable_constant_folding: !fold_on)
      program = RunarCompiler.compile_source_to_ir(path, disable_constant_folding: !fold_on)
      [artifact, canonical_anf(program)]
    end
  end

  # The ANF IR as JSON without source locations (which name the surface file).
  def canonical_anf(program)
    strip = lambda do |v|
      case v
      when Hash then v.reject { |k, _| k == 'sourceLoc' }.transform_values { |x| strip.call(x) }
      when Array then v.map { |x| strip.call(x) }
      else v
      end
    end
    JSON.generate(sort_keys(strip.call(RunarCompiler.send(:_serialize_anf_program, program))))
  end

  def sort_keys(v)
    case v
    when Hash then v.keys.sort.to_h { |k| [k, sort_keys(v[k])] }
    when Array then v.map { |x| sort_keys(x) }
    else v
    end
  end

  def slot_names(artifact)
    artifact.constructor_slots.map { |s| artifact.abi.constructor.params[s.param_index].name }
  end

  def sighash_of(artifact, method)
    artifact.abi.methods.find { |m| m.name == method }.sig_hash_type
  end

  def parse_errors(src, file_name)
    RunarCompiler.send(:_parse_source, src, file_name).errors
                 .select { |d| d.severity == RunarCompiler::Frontend::Severity::ERROR }
                 .map(&:message)
  end

  # Replace exactly one occurrence, so a stale needle fails loudly.
  def swap(src, from, to)
    assert_equal 1, src.scan(from).length, "needle not found exactly once: #{from.inspect}"
    src.sub(from) { to }
  end

  [false, true].each do |fold_on|
    SURFACES.each do |ext, directives, embed_tags|
      define_method("test_native_directives_match_ts_reference_#{slug(ext)}_fold_#{fold_on ? 'on' : 'off'}") do
        ts_dir, ts_anf = build(self.class.read('ts/compiler-directives/Directives.runar.ts'), 'Directives.runar.ts', fold_on)
        ts_emb, = build(self.class.read('ts/compiler-directives/EmbedTags.runar.ts'), 'EmbedTags.runar.ts', fold_on)
        assert_equal DIRECTIVES_HEX, ts_dir.script, '.runar.ts Directives drifted'
        assert_equal EMBED_TAGS_HEX, ts_emb.script, '.runar.ts EmbedTags drifted'

        r, anf = build(self.class.read(directives), "Directives#{ext}", fold_on)
        assert_equal DIRECTIVES_HEX, r.script
        assert_includes slot_names(r), 'deployTag'
        assert_equal SINGLE_FORKID, sighash_of(r, 'spendSingle')
        assert_nil sighash_of(r, 'spendAll')
        assert_equal ts_anf, anf, 'ANF differs from the .runar.ts original'
        unless embed_tags.nil?
          e, = build(self.class.read(embed_tags), "EmbedTags#{ext}", fold_on)
          assert_equal EMBED_TAGS_HEX, e.script
        end
      end
    end
  end

  NON_PUBLIC = '@sighash directive on non-public method'
  MULTIPLE = 'more than one @sighash directive on this method'
  MALFORMED = '@sighash: malformed directive'
  NO_FORKID = 'FORKID is mandatory on BSV'
  LOST_SIGHASH = '@sighash directive is not attached to any method'
  LOST_EMBED = '@embedAlways directive is not attached to any property'

  # [extension, label, from, to, expected error substring]
  NEGATIVES = [
    ['.runar.sol', 'no FORKID', 'sighash(SINGLE | FORKID)', 'sighash(SINGLE)', NO_FORKID],
    ['.runar.sol', 'comma-separated', 'sighash(SINGLE | FORKID)', 'sighash(SINGLE, FORKID)', MALFORMED],
    ['.runar.sol', 'two modifiers', 'sighash(SINGLE | FORKID)', 'sighash(SINGLE | FORKID) sighash(ALL | FORKID)', MULTIPLE],
    ['.runar.sol', 'private method', 'public sighash(SINGLE | FORKID)', 'private sighash(SINGLE | FORKID)', NON_PUBLIC],
    ['.runar.move', 'no FORKID', '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE)]', NO_FORKID],
    ['.runar.move', 'comma-separated', '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE, FORKID)]', MALFORMED],
    ['.runar.move', 'two attributes', '#[sighash(SINGLE | FORKID)]', "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", MULTIPLE],
    ['.runar.move', 'private fun', 'public fun spend_single', 'fun spend_single', NON_PUBLIC],
    ['.runar.move', 'sighash on a field', '#[embed_always]', '#[sighash(SINGLE | FORKID)]', LOST_SIGHASH],
    ['.runar.move', 'embed_always on a fun', '#[sighash(SINGLE | FORKID)]', '#[embed_always]', LOST_EMBED],
    ['.runar.move', 'unknown attribute', '#[sighash(SINGLE | FORKID)]', '#[test]', 'unsupported Move attribute #[test]'],
    ['.runar.go', 'no FORKID', '//runar:sighash SINGLE|FORKID', '//runar:sighash SINGLE', NO_FORKID],
    ['.runar.go', 'comma-separated', '//runar:sighash SINGLE|FORKID', '//runar:sighash SINGLE,FORKID', MALFORMED],
    ['.runar.go', 'glued', '//runar:sighash SINGLE|FORKID', '//runar:sighashSINGLE|FORKID', "unknown Go DSL directive '//runar:sighashSINGLE|FORKID'"],
    ['.runar.go', 'two directives', '//runar:sighash SINGLE|FORKID', "//runar:sighash SINGLE|FORKID\n//runar:sighash ALL|FORKID", MULTIPLE],
    ['.runar.go', 'unexported method', "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) SpendSingle", "//runar:sighash SINGLE|FORKID\nfunc (c *Directives) spendSingleHelper() {}\n\nfunc (c *Directives) SpendSingle", NON_PUBLIC],
    ['.runar.go', 'not above a func', 'type Directives struct', "//runar:sighash SINGLE|FORKID\ntype Directives struct", LOST_SIGHASH],
    ['.runar.go', 'unknown directive', '//runar:sighash SINGLE|FORKID', '//runar:inline', "unknown Go DSL directive '//runar:inline'"],
    ['.runar.rs', 'no FORKID', '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE)]', NO_FORKID],
    ['.runar.rs', 'comma-separated', '#[sighash(SINGLE | FORKID)]', '#[sighash(SINGLE, FORKID)]', MALFORMED],
    ['.runar.rs', 'two attributes', '#[sighash(SINGLE | FORKID)]', "#[sighash(SINGLE | FORKID)]\n    #[sighash(ALL | FORKID)]", MULTIPLE],
    ['.runar.rs', 'private fn', 'pub fn spend_single', 'fn spend_single', NON_PUBLIC],
    ['.runar.rs', 'sighash on a field', '#[embed_always]', '#[sighash(SINGLE | FORKID)]', LOST_SIGHASH],
    ['.runar.rs', 'embed_always on a fn', '#[sighash(SINGLE | FORKID)]', '#[embed_always]', LOST_EMBED],
    ['.runar.py', 'no FORKID', '@public(sighash="SINGLE|FORKID")', '@public(sighash="SINGLE")', NO_FORKID],
    ['.runar.py', 'non-string argument', '@public(sighash="SINGLE|FORKID")', '@public(sighash=SINGLE)', MALFORMED],
    ['.runar.py', 'unknown keyword', '@public(sighash="SINGLE|FORKID")', '@public(mode="SINGLE|FORKID")', MALFORMED],
    ['.runar.py', 'two decorators', '@public(sighash="SINGLE|FORKID")', "@public(sighash=\"SINGLE|FORKID\")\n    @public(sighash=\"ALL|FORKID\")", MULTIPLE],
    ['.runar.zig', 'no FORKID', 'runar.Sighash("SINGLE|FORKID")', 'runar.Sighash("SINGLE")', NO_FORKID],
    ['.runar.zig', 'non-string argument', 'runar.Sighash("SINGLE|FORKID")', 'runar.Sighash(SINGLE)', MALFORMED],
    ['.runar.zig', 'private fn', 'pub fn spendSingle', 'fn spendSingle', NON_PUBLIC],
    ['.runar.rb', 'no FORKID', "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE'", NO_FORKID],
    ['.runar.rb', 'symbol argument', "runar_sighash 'SINGLE|FORKID'", 'runar_sighash :single', MALFORMED],
    ['.runar.rb', 'two macros', "runar_sighash 'SINGLE|FORKID'", "runar_sighash 'SINGLE|FORKID'\n  runar_sighash 'ALL|FORKID'", MULTIPLE],
    ['.runar.rb', 'private method', "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_sighash 'SINGLE|FORKID'\n", NON_PUBLIC],
    ['.runar.rb', 'no following def', "\nend\n", "\n\n  runar_sighash 'ALL|FORKID'\nend\n", LOST_SIGHASH],
    ['.runar.java', 'no FORKID', '@Sighash("SINGLE|FORKID")', '@Sighash("SINGLE")', NO_FORKID],
    ['.runar.java', 'non-string argument', '@Sighash("SINGLE|FORKID")', '@Sighash(1)', MALFORMED],
    ['.runar.java', 'two annotations', '@Sighash("SINGLE|FORKID")', "@Sighash(\"SINGLE|FORKID\")\n    @Sighash(\"ALL|FORKID\")", MULTIPLE],
    ['.runar.java', 'no @Public', "    @Public\n    @Sighash", '    @Sighash', NON_PUBLIC],
    ['.runar.java', '@Sighash on a field', '@Readonly @EmbedAlways ByteString', '@Readonly @Sighash("ALL|FORKID") ByteString', LOST_SIGHASH],
    ['.runar.java', '@EmbedAlways on a method', '@Sighash("SINGLE|FORKID")', '@EmbedAlways', LOST_EMBED],
  ].freeze

  NEGATIVES.each do |ext, label, from, to, want|
    define_method("test_malformed_native_spelling_refused_#{slug(ext)}_#{slug(label)}") do
      errs = parse_errors(swap(self.class.directives_of(ext), from, to), "Directives#{ext}")
      assert_includes errs.join("\n"), want, "#{ext}: #{label}: got #{errs.inspect}"
    end
  end

  # [label, extension, from, to, check: :hex | :sighash | :no_deploy_tag]
  COMPOSITIONS = [
    ['rs: #[embed_always] before #[readonly]', '.runar.rs', "#[readonly]\n    #[embed_always]", "#[embed_always]\n    #[readonly]", :hex],
    ['rs: #[runar::sighash(...)]', '.runar.rs', '#[sighash(', '#[runar::sighash(', :sighash],
    ['py: Readonly[EmbedAlways[T]]', '.runar.py', 'EmbedAlways[ByteString]', 'Readonly[EmbedAlways[ByteString]]', :hex],
    ['zig: runar.Readonly(runar.EmbedAlways(T))', '.runar.zig', 'runar.EmbedAlways(runar.ByteString)', 'runar.Readonly(runar.EmbedAlways(runar.ByteString))', :hex],
    ['sol: embedAlways before immutable', '.runar.sol', 'ByteString immutable embedAlways deployTag', 'ByteString embedAlways immutable deployTag', :hex],
    ['rb: runar_sighash after runar_public', '.runar.rb', "runar_sighash 'SINGLE|FORKID'\n  runar_public sig: Sig, pub_key: PubKey\n", "runar_public sig: Sig, pub_key: PubKey\n  runar_sighash 'SINGLE|FORKID'\n", :sighash],
    ['go: doc comment between directive and func', '.runar.go', "//runar:sighash SINGLE|FORKID\n", "//runar:sighash SINGLE|FORKID\n// SpendSingle commits to one output.\n", :sighash],
    ['go: tag without embedAlways is not embedded', '.runar.go', '`runar:"readonly,embedAlways"`', '`runar:"readonly"`', :no_deploy_tag],
  ].freeze

  COMPOSITIONS.each do |label, ext, from, to, check|
    define_method("test_native_spellings_compose_with_readonly_#{slug(label)}") do
      r, = build(swap(self.class.directives_of(ext), from, to), "Directives#{ext}", false)
      case check
      when :hex then assert_equal DIRECTIVES_HEX, r.script, label
      when :sighash then assert_equal SINGLE_FORKID, sighash_of(r, 'spendSingle'), label
      else refute_includes slot_names(r), 'deployTag', label
      end
    end
  end

  COMMENT_NAMES = [
    ['.runar.sol', 'Solidity', 'solidity', 'the function modifier sighash(<FLAGS>)', 'the property modifier embedAlways'],
    ['.runar.move', 'Move', 'move', 'the attribute #[sighash(<FLAGS>)]', 'the attribute #[embed_always]'],
    ['.runar.go', 'Go DSL', 'go', 'the directive //runar:sighash <FLAGS>', 'the struct tag option runar:"readonly,embedAlways"'],
    ['.runar.rs', 'Rust', 'rust', 'the attribute #[sighash(<FLAGS>)]', 'the attribute #[embed_always]'],
    ['.runar.py', 'Python', 'python', '@public(sighash="<FLAGS>")', 'the wrapper type EmbedAlways[T]'],
    ['.runar.zig', 'Zig', 'zig', 'the return type runar.Sighash("<FLAGS>")', 'the type function runar.EmbedAlways(T)'],
    ['.runar.rb', 'Ruby', 'ruby', "runar_sighash '<FLAGS>'", 'the prop option embed_always: true'],
    ['.runar.java', 'Java', 'java', 'the annotation @Sighash("<FLAGS>")', 'the annotation @EmbedAlways'],
  ].freeze

  COMMENT_NAMES.each do |ext, surface, doc, sig, emb|
    define_method("test_comment_directive_on_non_ts_surface_names_native_spelling_#{slug(ext)}") do
      src = self.class.directives_of(ext)
      comment = %w[.runar.py .runar.rb].include?(ext) ? '#' : '//'
      file_name = "Directives#{ext}"
      assert_equal [
        "@sighash directive (issue #123) is not supported as a comment by the #{surface} surface parser; " \
        "write it as #{sig} (see docs/formats/#{doc}.md)",
      ], parse_errors("#{comment} @sighash SINGLE|FORKID\n#{src}", file_name)
      assert_equal [
        "@embedAlways directive (issue #109) is not supported as a comment by the #{surface} surface parser; " \
        "write it as #{emb} (see docs/formats/#{doc}.md)",
      ], parse_errors("#{comment} @embedAlways\n#{src}", file_name)
    end
  end

  # The constructor / init cases the TS reference refuses with
  # lost_directive_message: a constructor is neither a spending entry point nor
  # a field, so a sighash (or Java @EmbedAlways) on it would be dropped silently.
  CONSTRUCTOR_CASES = [
    ['.runar.rs', '    pub fn spend_all', "    #[sighash(ALL | FORKID)]\n    pub fn init(&mut self) {}\n\n    pub fn spend_all", LOST_SIGHASH],
    ['.runar.zig', ', deployTag: runar.ByteString) Directives {', ', deployTag: runar.ByteString) runar.Sighash("ALL|FORKID") {', LOST_SIGHASH],
    ['.runar.py', '    def __init__', "    @public(sighash=\"ALL|FORKID\")\n    def __init__", LOST_SIGHASH],
    ['.runar.rb', '  def initialize', "  runar_sighash 'ALL|FORKID'\n  def initialize", LOST_SIGHASH],
    ['.runar.java', '    Directives(Addr', "    @Sighash(\"ALL|FORKID\")\n    Directives(Addr", LOST_SIGHASH],
    ['.runar.java', '    Directives(Addr', "    @EmbedAlways\n    Directives(Addr", LOST_EMBED],
  ].freeze

  CONSTRUCTOR_CASES.each do |ext, from, to, want|
    define_method("test_directive_on_constructor_refused_#{slug(ext)}_#{slug(want[0, 13])}") do
      errs = parse_errors(swap(self.class.directives_of(ext), from, to), "Directives#{ext}")
      assert_includes errs.join("\n"), want, "#{ext}: got #{errs.inspect}"
    end
  end
end
