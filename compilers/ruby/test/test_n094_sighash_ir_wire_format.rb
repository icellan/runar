# frozen_string_literal: true

# N-094 — the `--emit-ir` ANF wire format must carry `@sighash` losslessly.
#
# `--emit-ir` is a supported CLI mode and ANF is the declared conformance
# boundary, so ANF emitted by this tier is fed back into `--ir` (here, and by
# any other tier's loader) to produce a deployable locking script. A method
# declaring `/** @sighash SINGLE|FORKID */` compiles the BIP-143 flag byte
# 0x43 into the OP_PUSH_TX binding; when the flag is dropped from (or
# misspelled in) the emitted ANF the loader falls back to the default
# ALL|FORKID and the binding silently becomes 0x41. Same script length, one
# byte different — a covenant bound to the wrong sighash mode.
#
# Every assertion here is on the ROUND-TRIPPED SCRIPT HEX, not on the presence
# of a JSON key: the key is the mechanism, the byte is the harm.

require 'json'
require 'open3'
require 'set'
require 'tmpdir'
require_relative 'test_helper'
require 'runar_compiler/cli'

class TestN094SighashIRWireFormat < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  RUBY_CLI = File.join(RUBY_COMPILER_DIR, 'bin/runar-compiler-ruby')
  REPO_ROOT = File.expand_path('../..', RUBY_COMPILER_DIR)
  ANF_SCHEMA = File.join(REPO_ROOT, 'packages/runar-ir-schema/src/schemas/anf-ir.schema.json')
  GO_CLI = File.join(REPO_ROOT, 'compilers/go/runar-go')

  # SIGHASH_SINGLE | SIGHASH_FORKID.
  SIGHASH_SINGLE_FORKID = 0x43

  # Stateless contract with a manual checkPreimage under a non-default mode.
  SIGHASH_SRC = <<~TS
    import { SmartContract, SigHashPreimage, assert, checkPreimage } from "runar-lang";

    class C extends SmartContract {
      readonly s: bigint;

      constructor(s: bigint) { super(s); this.s = s; }

      /** @sighash SINGLE|FORKID */
      public m(flag: bigint, pre: SigHashPreimage): void {
        if (flag > 0n) {
          assert(checkPreimage(pre));
        } else {
          assert(flag <= 0n);
        }
        assert(this.s >= 0n);
      }
    }
  TS

  # Control: byte-for-byte the same contract with NO @sighash directive, so the
  # covenant runs under the default ALL|FORKID and the ANF carries no flag.
  DEFAULT_SRC = SIGHASH_SRC.sub("  /** @sighash SINGLE|FORKID */\n", '')

  # Control: no checkPreimage at all — nothing for the flag to ride on.
  NO_PREIMAGE_SRC = <<~TS
    import { SmartContract, assert } from "runar-lang";

    class C extends SmartContract {
      readonly s: bigint;

      constructor(s: bigint) { super(s); this.s = s; }

      public m(flag: bigint): void {
        assert(flag > 0n);
        assert(this.s >= 0n);
      }
    }
  TS

  def run_cli(*args)
    Open3.capture3('ruby', '-I', File.join(RUBY_COMPILER_DIR, 'lib'), RUBY_CLI, *args)
  end

  def with_source(src)
    Dir.mktmpdir('n094') do |dir|
      path = File.join(dir, 'C.runar.ts')
      File.write(path, src)
      yield dir, path
    end
  end

  # --source -> hex, --emit-ir -> --ir -> hex. Returns [direct_hex, round_hex, ir_json].
  def round_trip(src)
    with_source(src) do |dir, path|
      direct, err, st = run_cli('--source', path, '--hex')
      assert st.success?, "--source --hex failed: #{err}"

      ir, err, st = run_cli('--source', path, '--emit-ir')
      assert st.success?, "--emit-ir failed: #{err}"

      ir_path = File.join(dir, 'ir.json')
      File.write(ir_path, ir)
      round, err, st = run_cli('--ir', ir_path, '--hex')
      assert st.success?, "--ir --hex failed: #{err}"

      return [direct.strip, round.strip, ir]
    end
  end

  # Every `check_preimage` node anywhere in the program.
  def check_preimage_nodes(ir)
    found = []
    walk = lambda do |node|
      case node
      when Hash
        found << node if node['kind'] == 'check_preimage'
        node.each_value { |v| walk.call(v) }
      when Array
        node.each { |v| walk.call(v) }
      end
    end
    walk.call(JSON.parse(ir))
    found
  end

  # -------------------------------------------------------------------------
  # The harm: the round-tripped script byte
  # -------------------------------------------------------------------------

  def test_sighash_survives_the_emit_ir_round_trip
    direct, round, = round_trip(SIGHASH_SRC)

    refute_empty direct
    assert_equal direct, round,
                 "--emit-ir -> --ir changed the compiled script.\n" \
                 "The @sighash flag byte did not survive the ANF wire format:\n" \
                 "  direct: #{direct}\n  round : #{round}"
  end

  def test_round_tripped_script_still_commits_to_single_forkid
    direct, round, = round_trip(SIGHASH_SRC)
    default, = round_trip(DEFAULT_SRC)

    # Sanity: the two modes differ, and only in the flag byte, so an equality
    # assertion above is actually load-bearing (same length, one byte apart).
    assert_equal default.length, direct.length,
                 'expected SINGLE|FORKID and the default mode to be the same script length'
    refute_equal default, direct,
                 'expected @sighash SINGLE|FORKID to change the compiled script'
    refute_equal default, round,
                 'the round-tripped script silently downgraded to the DEFAULT sighash mode'
  end

  # -------------------------------------------------------------------------
  # Controls
  # -------------------------------------------------------------------------

  def test_control_default_mode_round_trips_byte_identically
    direct, round, ir = round_trip(DEFAULT_SRC)
    assert_equal direct, round, 'default-sighash contract no longer round-trips'
    check_preimage_nodes(ir).each do |n|
      refute n.key?('sighashFlag'),
             'default mode must omit sighashFlag so pre-existing goldens stay byte-identical'
    end
  end

  def test_control_contract_without_check_preimage_round_trips
    direct, round, ir = round_trip(NO_PREIMAGE_SRC)
    assert_equal direct, round, 'contract without checkPreimage no longer round-trips'
    assert_empty check_preimage_nodes(ir)
  end

  # -------------------------------------------------------------------------
  # Wire-format shape (the mechanism behind the byte)
  # -------------------------------------------------------------------------

  def test_check_preimage_carries_camelcase_sighash_flag
    _, _, ir = round_trip(SIGHASH_SRC)
    nodes = check_preimage_nodes(ir)
    assert_equal 1, nodes.size, 'expected exactly one check_preimage node'
    node = nodes.first

    refute node.key?('sighash_flag'),
           'snake_case sighash_flag is not the wire spelling; Go/Zig/Rust/Java read sighashFlag'
    assert_equal SIGHASH_SINGLE_FORKID, node['sighashFlag'],
                 "check_preimage lost the declared @sighash mode: #{node.inspect}"
  end

  def test_no_method_carries_a_stray_sighash_type
    _, _, ir = round_trip(SIGHASH_SRC)
    JSON.parse(ir)['methods'].each do |m|
      refute m.key?('sighash_type'),
             "method #{m['name']} leaks the in-memory sighash_type carrier into the ANF wire format"
      refute m.key?('sighashType'),
             "method #{m['name']} leaks the in-memory sighash_type carrier into the ANF wire format"
    end
  end

  # -------------------------------------------------------------------------
  # Cross-tier: the reported reproduction. Go loads our ANF.
  # -------------------------------------------------------------------------

  def test_go_compiles_our_anf_to_the_same_script
    skip "go compiler binary not built at #{GO_CLI}" unless File.executable?(GO_CLI)

    with_source(SIGHASH_SRC) do |dir, path|
      go_direct, err, st = Open3.capture3(GO_CLI, '--source', path, '--hex')
      assert st.success?, "go --source --hex failed: #{err}"

      ir, err, st = run_cli('--source', path, '--emit-ir')
      assert st.success?, "--emit-ir failed: #{err}"
      ir_path = File.join(dir, 'ir.json')
      File.write(ir_path, ir)

      go_round, err, st = Open3.capture3(GO_CLI, '--ir', ir_path, '--hex')
      assert st.success?, "go --ir --hex failed: #{err}"

      assert_equal go_direct.strip, go_round.strip,
                   'Go compiled a DIFFERENT script from our ANF than from the same source'
    end
  end

  # -------------------------------------------------------------------------
  # Lockstep guard — the class of defect, not this instance.
  #
  # The wire names the ANF JSON may use are fixed by the cross-tier JSON
  # Schema in packages/runar-ir-schema. Every field an ANF node type declares
  # must therefore either (a) serialize to a key that schema knows, and
  # actually appear in the serializer's output, or (b) be listed in the
  # serializer's documented exclusion set. A field that is neither is a field
  # the serializer silently drops or misspells — exactly what happened to
  # sighash_flag. The field list is read off the TYPE, so this fires the
  # moment the type gains a field the serializer does not handle.
  # -------------------------------------------------------------------------

  # Fields this tier emits under a name the ANF JSON Schema does not list.
  #
  # EMPTY, and it must stay that way: an entry here is a field whose bytes no
  # other tier can read. N-095 emptied it by settling `synthetic_array_chain`
  # on the Go spelling (`syntheticArrayChain`) and declaring it in
  # `$defs.ANFProperty`, so this guard -- not a comment -- is now what stops
  # the spelling from splitting three ways again.
  SCHEMA_DIVERGENCES = [].freeze

  # Wire keys the ANF JSON Schema accepts anywhere in the document.
  def schema_wire_keys
    schema = JSON.parse(File.read(ANF_SCHEMA))
    keys = Set.new(schema.fetch('properties').keys)
    schema.fetch('$defs').each_value do |d|
      keys.merge(d['properties'].keys) if d.is_a?(Hash) && d['properties'].is_a?(Hash)
    end
    keys
  end

  # A sentinel for each field, chosen so the serializer's non-nil test passes
  # and nested walks do not explode.
  def populate(obj, fields, kind)
    fields.each do |f|
      val = case f.to_s
            when 'kind' then kind
            when 'then', 'else_', 'body', 'args', 'state_values', 'elements',
                 'params', 'properties', 'methods', 'synthetic_array_chain' then []
            # Non-empty: the artifact ANF serializer skips an empty +results+.
            when 'results' then ['x']
            when 'count', 'start', 'step', 'in_arity', 'out_arity', 'sighash_flag',
                 'sighash_type', 'line', 'column' then 1
            when 'readonly', 'is_public', 'is_auto_injected_state_check', 'preserve' then true
            when 'value' then RunarCompiler::IR::ANFValue.new(kind: 'get_state_script')
            when 'source_loc' then RunarCompiler::IR::SourceLocation.new
            when 'raw_value' then '"x"'
            else 'x'
            end
      obj.respond_to?(:[]=) && obj.is_a?(Struct) ? obj[f] = val : obj.send("#{f}=", val)
    end
    obj
  end

  def assert_fields_are_all_accounted_for(node, fields, label, wire_keys)
    # A few fields are emitted only for one +kind+ (isAutoInjectedStateCheck
    # rides on +assert+, sighashFlag on +check_preimage+), so serialize the
    # fully-populated node once per discriminator and union the wire keys.
    emitted = %w[assert check_preimage].flat_map do |kind|
      RunarCompiler::CLI._anf_to_camel_dict(populate(node, fields, kind)).keys
    end.uniq
    excluded = RunarCompiler::CLI::IR_EXCLUDED_FIELDS

    fields.map(&:to_s).each do |f|
      next if excluded.include?(f)

      key = RunarCompiler::CLI._snake_key(f)
      unless SCHEMA_DIVERGENCES.include?(f)
        assert_includes wire_keys, key,
                        "#{label}.#{f} serializes to \"#{key}\", which the cross-tier ANF JSON " \
                        "Schema does not accept. Fix the wire name, or exclude the field."
      end
      assert_includes emitted, key,
                      "#{label}.#{f} never reaches the emitted ANF (expected key \"#{key}\"). " \
                      'Fields dropped here vanish silently: the Go loader ignores unknown keys.'
    end
  end

  def test_every_anf_field_is_either_emitted_or_explicitly_excluded
    wire_keys = schema_wire_keys
    ir = RunarCompiler::IR

    value = ir::ANFValue.new(kind: 'check_preimage')
    value_fields = value.instance_variables.map { |s| s.to_s.delete_prefix('@').to_sym }
    assert_includes value_fields, :sighash_flag, 'ANFValue no longer declares sighash_flag'
    assert_fields_are_all_accounted_for(value, value_fields, 'ANFValue', wire_keys)

    {
      'ANFProgram' => ir::ANFProgram.new,
      'ANFProperty' => ir::ANFProperty.new,
      'ANFMethod' => ir::ANFMethod.new,
      'ANFParam' => ir::ANFParam.new,
      'ANFBinding' => ir::ANFBinding.new,
    }.each do |label, node|
      assert_fields_are_all_accounted_for(node, node.members, label, wire_keys)
    end
  end

  # -------------------------------------------------------------------------
  # The SECOND ANF serializer in this tier.
  #
  # +Compiler::_serialize_anf_program+ fills the +anf+ field the artifact
  # carries for every STATEFUL contract -- the copy SDK ANF interpreters read.
  # It is a third hand-maintained enumeration of the same field list (the
  # emit allowlist and the rename table were the other two), so it gets the
  # same field-coverage guard.
  # -------------------------------------------------------------------------

  # Fully-populated ANFValue serialized through the artifact ANF serializer,
  # unioned over the discriminators that gate a field (+assert+ gates
  # isAutoInjectedStateCheck, +raw_script+ the byte span, and so on).
  def artifact_anf_value_keys(fields)
    ir = RunarCompiler::IR
    %w[assert check_preimage raw_script array_literal].flat_map do |kind|
      program = ir::ANFProgram.new(
        contract_name: 'C',
        properties: [],
        methods: [ir::ANFMethod.new(
          name: 'm',
          params: [],
          body: [ir::ANFBinding.new(
            name: 't0',
            value: populate(ir::ANFValue.new(kind: kind), fields, kind),
          )],
          is_public: true,
        )],
      )
      RunarCompiler.send(:_serialize_anf_program, program)['methods'][0]['body'][0]['value'].keys
    end.uniq
  end

  def test_artifact_anf_serializer_emits_every_declared_field
    wire_keys = schema_wire_keys
    fields = RunarCompiler::IR::ANFValue::FIELDS
    emitted = artifact_anf_value_keys(fields)
    excluded = RunarCompiler::CLI::IR_EXCLUDED_FIELDS

    fields.map(&:to_s).each do |f|
      next if excluded.include?(f)

      key = RunarCompiler::CLI._snake_key(f)
      assert_includes emitted, key,
                      "ANFValue.#{f} never reaches the artifact's embedded ANF " \
                      "(expected key \"#{key}\"). Stateful artifacts carry that ANF to the " \
                      'SDK interpreters, so a field dropped here is a field they cannot see.'
      assert_includes wire_keys, key, "unexpected wire key \"#{key}\" for ANFValue.#{f}"
    end
  end

  # The concrete harm behind the guard above: a stateful contract whose body
  # builds an array (checkMultiSig) must carry the array's element refs.
  MULTISIG_STATEFUL_SRC = <<~TS
    import { StatefulSmartContract, assert, checkMultiSig, PubKey, Sig } from "runar-lang";

    class Arr2 extends StatefulSmartContract {
      n: bigint;
      readonly a: PubKey;
      readonly b: PubKey;

      constructor(n: bigint, a: PubKey, b: PubKey) { super(n, a, b); this.n = n; this.a = a; this.b = b; }

      public bump(s1: Sig, s2: Sig): void {
        assert(checkMultiSig([s1, s2], [this.a, this.b]));
        this.n = this.n + 1n;
      }
    }
  TS

  def test_stateful_artifact_anf_keeps_array_literal_elements
    with_source(MULTISIG_STATEFUL_SRC) do |_dir, path|
      out, err, st = run_cli('--source', path)
      assert st.success?, "--source failed: #{err}"

      artifact = JSON.parse(out)
      anf = artifact['anf']
      refute_nil anf, 'a stateful contract must carry its ANF in the artifact'

      nodes = []
      walk = lambda do |n|
        case n
        when Hash
          nodes << n if n['kind'] == 'array_literal'
          n.each_value { |v| walk.call(v) }
        when Array then n.each { |v| walk.call(v) }
        end
      end
      walk.call(anf)

      refute_empty nodes, 'expected checkMultiSig to lower to array_literal nodes'
      nodes.each do |n|
        refute_nil n['elements'],
                   "array_literal in the artifact ANF has no elements: #{n.inspect}. " \
                   'The Go reference emits {"kind":"array_literal","elements":[...]}; without ' \
                   'them an SDK ANF interpreter cannot rebuild the array.'
        refute_empty n['elements']
      end
    end
  end
end
