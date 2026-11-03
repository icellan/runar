# frozen_string_literal: true

require 'json'
require 'pathname'
require 'spec_helper'
require 'runar/sdk'

# F-274 (CL-BUG-163): both Ruby runtimes of `left`/`right` must return what the
# COMPILED SCRIPT returns, for every vector in the shared on-chain file
# packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json.
#
# That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
# packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts.
# `right(data, 0)` used to compute `data[-(0 * 2)..]`, which Ruby resolves to
# `data[-0..]` == `data[0..]` -- the WHOLE string, not the empty one the
# compiled script produces. `left`/`right` also returned a truncated or
# whole-string value (instead of raising) for a length outside
# `[0, data.length / 2]`.
#
# Proves: for every row, Runar::Builtins (what a .runar.rb contract calls
# under rspec) and the SDK ANF interpreter return the on-chain value, or raise
# where the script aborts (never a value) -- covering n=0, n=len(data),
# n>len(data), n<0, and an empty `data` input.
# Does not prove: inputs outside the file, or the script itself (the oracle).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'F-274 left/right return the on-chain value for every shared vector' do
  # rubocop:enable RSpec/DescribeClass
  vectors_path = Pathname.new(__dir__).ascend.map do |dir|
    dir.join('packages', 'runar-zig', 'src', 'fixtures', 'f274-split-builtins-onchain.json')
  end.find(&:file?)
  raise 'could not locate f274-split-builtins-onchain.json' unless vectors_path

  data = JSON.parse(vectors_path.read)
  rows = data['cases'].map { |c| [c['fn'], c['data'], c['n'], c['expect']] }

  native_names = { 'left' => :left, 'right' => :right }

  let(:ctx) { Object.new.extend(Runar::Builtins) }
  let(:mod) { Runar::SDK::ANFInterpreter }

  rows.each do |fn, hex, n, want|
    label = "#{fn}(#{hex.inspect}, #{n}) -> #{want.inspect}"

    it "native #{label}" do
      if want == 'abort'
        expect { ctx.public_send(native_names.fetch(fn), hex, n) }.to raise_error(StandardError)
      else
        expect(ctx.public_send(native_names.fetch(fn), hex, n)).to eq(want)
      end
    end

    it "interpreter #{label}" do
      if want == 'abort'
        expect { mod.eval_call(fn, [hex, n]) }.to raise_error(StandardError)
      else
        expect(mod.eval_call(fn, [hex, n])).to eq(want)
      end
    end
  end
end
