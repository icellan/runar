# frozen_string_literal: true

require 'json'
require 'pathname'
require 'spec_helper'

# N-111: the Ruby native EC builtins (Runar::EC, what a .runar.rb contract
# calls under rspec) must apply the compiled script's operand gates --
# ec_add / ec_negate: 64 bytes and x, y < p (R-117); ec_mul: on-curve or the
# all-zero identity O (R-157); ec_point_x / ec_point_y / ec_encode_compressed:
# width only -- and its addition law (inv(0) = 0, so an (x, 0) doubling is a
# value, not an error).
#
# Oracle: packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json,
# every row executed on @bsv/sdk Spend.validate by
# packages/runar-testing/src/__tests__/n111-ec-operand-gates-onchain.test.ts.
#
# Proves: for every row, each builtin returns the on-chain value, or raises
# where the script aborts (never a value).
# Does not prove: inputs outside the file, or the script itself.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'N-111 EC builtins match the on-chain operand gates' do
  # rubocop:enable RSpec/DescribeClass
  vectors_path = Pathname.new(__dir__).ascend.map do |dir|
    dir.join('packages', 'runar-zig', 'src', 'fixtures', 'n111-ec-operand-gates-onchain.json')
  end.find(&:file?)
  rows = JSON.parse(File.read(vectors_path))['cases']

  run = lambda do |row|
    p = row['p']
    k = row['k']&.to_i
    case row['fn']
    when 'ecAdd' then Runar::EC.ec_add(p, row['q'])
    when 'ecMul' then Runar::EC.ec_mul(p, k)
    when 'ecMulGen' then Runar::EC.ec_mul_gen(k)
    when 'ecNegate' then Runar::EC.ec_negate(p)
    when 'ecPointX' then Runar::EC.ec_point_x(p).to_s
    when 'ecPointY' then Runar::EC.ec_point_y(p).to_s
    when 'ecEncodeCompressed' then Runar::EC.ec_encode_compressed(p)
    when 'ecOnCurve' then Runar::EC.ec_on_curve(p).to_s
    else raise "unknown fn #{row['fn']}"
    end
  end

  rows.each_with_index do |row, i|
    it "#{i}: #{row['fn']} [#{row['why']}] -> #{row['expect'] == 'abort' ? 'abort' : 'value'}" do
      if row['expect'] == 'abort'
        expect { run.call(row) }.to raise_error(StandardError)
      else
        expect(run.call(row)).to eq(row['expect'])
      end
    end
  end
end
