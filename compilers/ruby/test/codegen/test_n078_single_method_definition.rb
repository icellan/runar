# frozen_string_literal: true

require_relative "../test_helper"
require_relative "codegen_helper"

# ---------------------------------------------------------------------------
# N-078: `_lower_get_state_script` was defined TWICE in `LoweringContext`.
#
# Ruby silently keeps the LAST definition; the first ~52 lines were dead code
# that still read as live. The hazard is not hypothetical — `b7e91a19`
# (N-067, the mutable-Rabin state width fix) had to patch BOTH copies
# identically, because a fix applied only to the first would have been
# discarded without a word. The two copies were never semantically divergent,
# but they were cosmetically divergent from birth (`5ef075da`), which is
# exactly what makes the next lockstep patch easy to get wrong.
#
# Two locks:
#   1. No method in this tier may be defined twice in the same lexical body.
#   2. The surviving `_lower_get_state_script` keeps its state-type
#      classification: the width comes from `numeric_state_type_width` and the
#      framing from `variable_length_state_type?`, so a mutable Rabin field
#      serializes exactly like `bigint` and a framed field does not.
# ---------------------------------------------------------------------------

class TestN078SingleMethodDefinition < Minitest::Test
  include CodegenTestHelpers

  LIB_ROOT = File.expand_path("../../lib", __dir__)

  # -------------------------------------------------------------------------
  # Lock 1 -- no silent redefinition anywhere in the Ruby compiler tier.
  # -------------------------------------------------------------------------

  def test_no_method_is_defined_twice_in_the_same_body
    unless defined?(RubyVM::AbstractSyntaxTree)
      skip "RubyVM::AbstractSyntaxTree unavailable on this Ruby"
    end

    offenders = []
    Dir.glob(File.join(LIB_ROOT, "**", "*.rb")).sort.each do |path|
      tree = RubyVM::AbstractSyntaxTree.parse_file(path)
      collect_duplicate_defs(tree, [], path, offenders)
    end

    assert_empty offenders,
                 "a method is defined more than once in the same body -- Ruby keeps only " \
                 "the LAST one and the earlier copies are dead code that still reads as " \
                 "live:\n  #{offenders.join("\n  ")}"
  end

  # -------------------------------------------------------------------------
  # Lock 2 -- the surviving definition's state-type classification.
  #
  # These are the exact lines the two copies expressed differently: the dead
  # copy dispatched on the NUMERIC_STATE_TYPES / VARIABLE_LENGTH_STATE_TYPES
  # sets, the live one on `numeric_state_type_width(...).positive?` and
  # `variable_length_state_type?`. Both agreed; pin that agreement so a future
  # edit to one form cannot silently change the state section.
  # -------------------------------------------------------------------------

  def state_script_src(prop_type)
    <<~TS
      class GetStateScriptShape extends StatefulSmartContract {
        tag: #{prop_type};
        constructor(tag: #{prop_type}) { super(tag); this.tag = tag; }
        public update(next: #{prop_type}) {
          this.tag = next;
          let s: ByteString = this.getStateScript();
          assert(len(s) > 0n);
        }
      }
    TS
  end

  def state_script(prop_type)
    compile_ts_source(state_script_src(prop_type), "GetStateScriptShape.runar.ts").script
  end

  def test_get_state_script_writes_rabin_at_the_bigint_width
    control = state_script("bigint")
    %w[RabinSig RabinPubKey].each do |t|
      assert_equal control, state_script(t),
                   "getStateScript serializes a mutable #{t} field differently from bigint -- " \
                   "the Rabin types are bigint aliases and the reader splits both at 8 bytes"
    end
  end

  def test_get_state_script_frames_variable_length_types_together
    control = state_script("ByteString")
    %w[Sig SigHashPreimage].each do |t|
      assert_equal control, state_script(t),
                   "getStateScript does not frame a mutable #{t} field like ByteString -- " \
                   "the deserializer decodes a push-data length prefix for all three"
    end
  end

  def test_get_state_script_classes_stay_distinct
    numeric = state_script("bigint")
    framed  = state_script("ByteString")
    raw     = state_script("PubKey")
    boolean = state_script("boolean")

    refute_equal numeric, framed, "numeric and framed state collapsed onto one shape"
    refute_equal numeric, raw,    "numeric and raw-width state collapsed onto one shape"
    refute_equal numeric, boolean, "the 8-byte and 1-byte numeric widths collapsed"
    refute_equal framed,  raw,    "framed and raw-width state collapsed onto one shape"
  end

  private

  # Walks the AST and reports any name defined twice as a DIRECT statement of
  # the same body. Ruby's own parser is used so that `Struct.new(...) do ... end`
  # blocks and nested classes are scoped correctly.
  def collect_duplicate_defs(node, scope, path, offenders)
    return unless node.is_a?(RubyVM::AbstractSyntaxTree::Node)

    inner = scope
    case node.type
    when :CLASS, :MODULE
      cpath = node.children[0]
      name = cpath.respond_to?(:children) ? cpath.children.compact.last : cpath
      inner = scope + ["#{node.type.to_s.downcase} #{name}"]
    when :SCLASS
      inner = scope + ["class<<self"]
    end

    if node.type == :BLOCK
      seen = Hash.new { |h, k| h[k] = [] }
      node.children.each do |child|
        next unless child.is_a?(RubyVM::AbstractSyntaxTree::Node)

        case child.type
        when :DEFN then seen[child.children[0].to_s] << child.first_lineno
        when :DEFS then seen["self.#{child.children[1]}"] << child.first_lineno
        end
      end
      seen.each do |name, lines|
        next if lines.size < 2

        rel = path.sub("#{File.dirname(LIB_ROOT)}/", "")
        offenders << "#{rel} [#{inner.join('/')}] #{name} at lines #{lines.sort.join(', ')}"
      end
    end

    node.children.each { |c| collect_duplicate_defs(c, inner, path, offenders) }
  end
end
