# frozen_string_literal: true

# EmbedTags (N-093): embed_always: true on a FixedArray prop with a default.
#
# The runar gem has no native FixedArray type (see fixed-array-nested,
# fixed-array-index), so -- like the other FixedArray examples -- this spec
# does not load the contract natively: it compiles it through the Ruby
# compiler and checks that all three tags are kept in the locking script
# although unlock reads only tags[1] (the .runar.ts original's script).

require_relative '../spec_helper'

compiler_lib = File.expand_path('../../../compilers/ruby/lib', __dir__)
$LOAD_PATH.unshift(compiler_lib) unless $LOAD_PATH.include?(compiler_lib)

require 'runar_compiler'

RSpec.describe 'EmbedTags' do
  let(:source_path) { File.expand_path('EmbedTags.runar.rb', __dir__) }

  it 'passes the Rúnar compile check' do
    expect(Runar.compile_check(source_path)).to be true
  end

  it 'embeds every tag (7, 9, 11) in the locking script, fold off and on' do
    [true, false].each do |disable_folding|
      art = RunarCompiler.compile_from_source(source_path, disable_constant_folding: disable_folding)
      expect(art.script).to eq('57595b537a59a2695379a90088547a547aac777777')
    end
  end
end
