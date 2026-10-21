# frozen_string_literal: true

require 'json'
require 'pathname'
require 'spec_helper'
require 'runar/sdk'

# N-030 (CL-BUG-104): both Ruby runtimes of the math builtins return what the
# COMPILED SCRIPT returns, for every vector in the shared on-chain file
# packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json.
#
# That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
# packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts
# (accept at `expect`, reject at `expect + 1`; an `abort` row rejects both
# `== 0` and `!= 0`). Every other tier replays the same file.
#
# Proves: for every `cases` and `wideCases` row, Runar::Builtins (what a
# .runar.rb contract calls under rspec) and the SDK ANF interpreter return the
# on-chain value, or raise where the script aborts (never a value) -- including
# clamp with lo > hi, log2 exact past 2^64 (N-103), gcd's partial remainder after 256
# Euclid steps, and abs/min/max existing natively at all.
# Does not prove: inputs outside the file, or the script itself (the oracle).
# Interpreter `bool`/`within` results are compared as script numbers
# (true == 1, false == 0).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-030 math builtins return the on-chain value for every shared vector' do
  # rubocop:enable RSpec/DescribeClass
  vectors_path = Pathname.new(__dir__).ascend.map do |dir|
    dir.join('packages', 'runar-zig', 'src', 'fixtures', 'f033-math-builtins-onchain.json')
  end.find(&:file?)
  raise 'could not locate f033-math-builtins-onchain.json' unless vectors_path

  data = JSON.parse(vectors_path.read)
  rows = data['cases'].map { |c| [c['fn'], c['args'], c['expect']] }
  data['wideCases'].each do |c|
    want = c['expect']
    want = Integer(want, 10) if want.is_a?(String) && want != 'abort'
    rows << [c['fn'], c['args'].map { |a| Integer(a, 10) }, want]
  end

  native_names = {
    'percentOf' => :percent_of, 'mulDiv' => :mul_div, 'safediv' => :safediv,
    'safemod' => :safemod, 'divmod' => :divmod, 'sqrt' => :sqrt, 'log2' => :log2,
    'pow' => :pow, 'clamp' => :clamp, 'within' => :within, 'sign' => :sign,
    'gcd' => :gcd, 'abs' => :abs, 'min' => :min, 'max' => :max, 'bool' => :bool
  }

  let(:ctx) { Object.new.extend(Runar::Builtins) }
  let(:mod) { Runar::SDK::ANFInterpreter }

  it 'covers every math builtin' do
    expect(rows.map(&:first).uniq.sort).to eq(native_names.keys.sort)
  end

  script_number = ->(v) { { true => 1, false => 0 }.fetch(v, v) }

  rows.each do |fn, args, want|
    label = "#{fn}(#{args.join(', ')})"[0, 140]

    it "native #{label} -> #{want}" do
      if want == 'abort'
        expect { ctx.public_send(native_names.fetch(fn), *args) }.to raise_error(StandardError)
      else
        expect(ctx.public_send(native_names.fetch(fn), *args)).to eq(want)
      end
    end

    it "interpreter #{label} -> #{want}" do
      if want == 'abort'
        expect { mod.eval_call(fn, args) }.to raise_error(StandardError)
      else
        expect(script_number.call(mod.eval_call(fn, args))).to eq(script_number.call(want))
      end
    end
  end
end
