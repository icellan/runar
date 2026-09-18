# frozen_string_literal: true

# Top-level require file for the Runar Ruby compiler.
#
# Loads the core compiler pipeline and CLI. Frontend and codegen modules
# are lazy-loaded on demand within compiler.rb methods.

# The oldest Ruby this tier runs on.
#
# `compilers/ruby` ships no gemspec and no Gemfile, so nothing else states a
# floor. `frontend/embed_always_dce.rb` calls `Enumerable#filter_map`, which
# arrived in Ruby 2.7; on 2.6 the suite dies while loading with
# `undefined method 'filter_map' for Array`, naming a method rather than a
# version. An external reviewer hit exactly that and could not run this tier.
#
# Checked before anything else is required, so the diagnostic beats the
# NoMethodError to the terminal. `test/test_minimum_ruby_version.rb` keeps this
# constant honest by scanning the sources for version-bearing calls — bump it
# when you reach for a newer one.
module RunarCompiler
  MINIMUM_RUBY_VERSION = "2.7.0"
end

if Gem::Version.new(RUBY_VERSION) < Gem::Version.new(RunarCompiler::MINIMUM_RUBY_VERSION)
  raise "runar-compiler-ruby requires Ruby >= #{RunarCompiler::MINIMUM_RUBY_VERSION}, " \
        "but this is #{RUBY_VERSION}. Enumerable#filter_map (Ruby 2.7) is used by " \
        "the frontend, so the compiler cannot load on an older interpreter."
end

require_relative "runar_compiler/ir/types"
require_relative "runar_compiler/ir/loader"
require_relative "runar_compiler/compiler"
require_relative "runar_compiler/cli"
