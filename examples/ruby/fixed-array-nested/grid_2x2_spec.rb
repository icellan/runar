# frozen_string_literal: true

# Nested FixedArray acceptance test for the Ruby compiler.
#
# Mirrors examples/python/fixed-array-nested/test_grid_2x2.py: compiles the
# Grid2x2 contract through the Ruby compiler frontend and verifies the
# +grid+ state field is regrouped into a single nested FixedArray entry.

require_relative '../spec_helper'

REPO_ROOT = File.expand_path('../../..', __dir__) unless defined?(REPO_ROOT)
$LOAD_PATH.unshift(File.join(REPO_ROOT, 'compilers', 'ruby', 'lib'))

require 'runar_compiler'

SOURCE_PATH = File.expand_path('Grid2x2.v2.runar.rb', __dir__) unless defined?(SOURCE_PATH)

RSpec.describe 'Grid2x2 nested FixedArray' do
  it 'compiles successfully' do
    art = RunarCompiler.compile_from_source(SOURCE_PATH)
    expect(art.contract_name).to eq('Grid2x2')
  end

  it 'exposes grid as a single nested FixedArray state field' do
    art = RunarCompiler.compile_from_source(SOURCE_PATH)
    grid = art.state_fields.find { |f| f.name == 'grid' }
    expect(grid).not_to be_nil
    expect(grid.type).to eq('FixedArray<FixedArray<bigint, 2>, 2>')
    expect(grid.fixed_array).not_to be_nil
    expect(grid.fixed_array[:length]).to eq(2)
    expect(grid.fixed_array[:element_type]).to eq('FixedArray<bigint, 2>')
    expect(grid.fixed_array[:synthetic_names]).to eq(%w[
      grid__0__0 grid__0__1 grid__1__0 grid__1__1
    ])
    expect(grid.initial_value).to eq([[0, 0], [0, 0]])
  end

  it 'does not leak intermediate names into top-level state fields' do
    art = RunarCompiler.compile_from_source(SOURCE_PATH)
    names = art.state_fields.map(&:name)
    expect(names).not_to include('grid__0')
    expect(names).not_to include('grid__1')
    expect(names).not_to include('grid__0__0')
  end
end
