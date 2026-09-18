# frozen_string_literal: true

# N-095 — the synthetic-array chain on +ANFProperty+ is wire data.
#
# The expand-fixed-arrays pass desugars a +FixedArray+ property into scalar
# siblings and hangs a chain of +{base, index, length}+ levels off each leaf.
# The artifact assembler regroups those siblings back into a single FixedArray
# state/ABI entry by reading that chain off the ANF PROGRAM, not off the AST --
# so an ANF that loses the field still compiles to byte-identical script but
# degrades the SDK's +state.grid+ accessor into four raw scalars. The harm is
# invisible to every hex-comparing test in the repo, which is why it survived.
#
# Ruby carried two distinct defects here:
#   1. it emitted +synthetic_array_chain+, a spelling no other tier reads and
#      which +$defs.ANFProperty+ (additionalProperties:false) rejects; and
#   2. +_anf_property_from_hash+ never read the key back at all, so Ruby wrote
#      a key it could not itself consume and its own ANF degraded on replay.
#
# The settled spelling is Go's +syntheticArrayChain+.

require 'json'
require 'tmpdir'
require_relative 'test_helper'
require 'runar_compiler/cli'
require 'runar_compiler/compiler'

class TestN095SyntheticArrayChain < Minitest::Test
  RUBY_COMPILER_DIR = File.expand_path('..', __dir__)
  REPO_ROOT = File.expand_path('../..', RUBY_COMPILER_DIR)
  ANF_SCHEMA = File.join(REPO_ROOT, 'packages/runar-ir-schema/src/schemas/anf-ir.schema.json')

  GRID_SRC = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';
    import type { FixedArray } from 'runar-lang';

    export class Grid2x2 extends StatefulSmartContract {
      grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

      constructor() {
        super();
      }

      public set00(v: bigint) {
        this.grid[0][0] = v;
        assert(true);
      }

      public set11(v: bigint) {
        this.grid[1][1] = v;
        assert(true);
      }
    }
  TS

  SCALAR_SRC = <<~TS
    import { StatefulSmartContract, assert } from 'runar-lang';

    export class Counter extends StatefulSmartContract {
      count: bigint = 0n;

      constructor() {
        super();
      }

      public increment() {
        this.count = this.count + 1n;
        assert(true);
      }
    }
  TS

  def with_source(src, name)
    Dir.mktmpdir do |dir|
      path = File.join(dir, name)
      File.write(path, src)
      yield dir, path
    end
  end

  # The ANF JSON this tier emits for +src+, parsed.
  def emit_ir(src, name = 'Grid2x2.runar.ts')
    with_source(src, name) do |_dir, path|
      program = RunarCompiler.compile_source_to_ir(path)
      return JSON.parse(JSON.generate(RunarCompiler::CLI._anf_to_camel_dict(program)))
    end
  end

  # Keys +$defs.ANFProperty+ accepts.
  def schema_property_keys
    schema = JSON.parse(File.read(ANF_SCHEMA))
    defn = schema.fetch('$defs').fetch('ANFProperty')
    assert_equal false, defn['additionalProperties'],
                 '$defs.ANFProperty is no longer additionalProperties:false — ' \
                 "this test's premise (an undeclared key is a schema violation) no longer holds"
    defn.fetch('properties').keys
  end

  def state_field_names(artifact)
    artifact.state_fields.map(&:name)
  end

  # -------------------------------------------------------------------------
  # Wire format
  # -------------------------------------------------------------------------

  def test_every_emitted_property_key_is_declared_in_the_schema
    allowed = schema_property_keys
    emit_ir(GRID_SRC).fetch('properties').each_with_index do |prop, i|
      prop.each_key do |key|
        assert_includes allowed, key,
                        "leaf #{i}: emitted ANFProperty key #{key.inspect} is not declared in " \
                        '$defs.ANFProperty (additionalProperties:false), so Ruby ANF fails validateANF'
      end
    end
  end

  def test_expanded_leaves_carry_the_camel_case_chain
    props = emit_ir(GRID_SRC).fetch('properties')
    assert_equal 4, props.size, 'expected 4 expanded leaves'

    want = [[0, 0], [0, 1], [1, 0], [1, 1]]
    props.each_with_index do |prop, i|
      refute prop.key?('synthetic_array_chain'),
             "leaf #{i} still emits the snake spelling no other tier reads"
      refute prop.key?('__syntheticArrayChain'),
             "leaf #{i} emits the TS AST-marker spelling"
      chain = prop['syntheticArrayChain']
      refute_nil chain, "leaf #{i} has no syntheticArrayChain key (keys: #{prop.keys.inspect})"
      assert_equal 2, chain.size, "leaf #{i}: a 2x2 grid nests twice"
      assert_equal 'grid', chain[0]['base'], "leaf #{i} outer base"
      assert_equal want[i][0], chain[0]['index'], "leaf #{i} outer index"
      assert_equal 2, chain[0]['length'], "leaf #{i} outer length"
      assert_equal want[i][1], chain[1]['index'], "leaf #{i} inner index"
      assert_equal 2, chain[1]['length'], "leaf #{i} inner length"
    end
  end

  # Byte-neutrality control: a FixedArray-free contract must not grow the key.
  def test_scalar_property_carries_no_chain
    emit_ir(SCALAR_SRC, 'Counter.runar.ts').fetch('properties').each do |prop|
      prop.each_key do |key|
        refute_match(/ynthetic/, key,
                     "a FixedArray-free contract grew a synthetic-array key: #{key}")
      end
    end
  end

  # -------------------------------------------------------------------------
  # The harm: the ABI, not the hex
  # -------------------------------------------------------------------------

  def test_self_ir_round_trip_still_regroups
    with_source(GRID_SRC, 'Grid2x2.runar.ts') do |dir, path|
      from_source = RunarCompiler.compile_from_source(path)
      assert_equal ['grid'], state_field_names(from_source),
                   'source mode no longer regroups the expanded leaves'

      ir_path = File.join(dir, 'ir.json')
      program = RunarCompiler.compile_source_to_ir(path)
      File.write(ir_path, JSON.generate(RunarCompiler::CLI._anf_to_camel_dict(program)))

      from_ir = RunarCompiler.compile_from_ir(ir_path)
      assert_equal ['grid'], state_field_names(from_ir),
                   'Ruby wrote an ANF it cannot read back: the FixedArray regrouping was lost, ' \
                   'so the SDK sees four raw scalars instead of state.grid'

      fa = from_ir.state_fields.first.fixed_array
      refute_nil fa, 'regrouped state field carries no fixedArray metadata'
      assert_equal %w[grid__0__0 grid__0__1 grid__1__0 grid__1__1], fa[:synthetic_names]

      assert_equal from_source.script, from_ir.script,
                   'the chain must be ABI-only: it must not move a single script byte'
    end
  end
end
