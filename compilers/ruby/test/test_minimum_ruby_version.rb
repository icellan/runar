# frozen_string_literal: true

require_relative "test_helper"
require "runar_compiler"

# The Ruby compiler tier must declare the Ruby version it actually needs.
#
# `compilers/ruby` ships no gemspec and no Gemfile — it is driven by its
# Rakefile — so nothing anywhere stated a minimum. It uses `filter_map`
# (Ruby 2.7+) in `frontend/embed_always_dce.rb`, so on Ruby 2.6 the suite dies
# during loading with `undefined method 'filter_map' for Array`. An external
# reviewer hit exactly that and could not run this tier at all; the error names
# a method, not a version, so the cause is not obvious from the failure.
#
# Two assertions, because a declared constant that drifts from the code is no
# better than no constant:
#   1. the floor exists and is enforced;
#   2. the floor is at least as high as the newest feature actually used.
class TestMinimumRubyVersion < Minitest::Test
  # Methods this tier calls that carry a Ruby version floor.
  VERSIONED_FEATURES = {
    ".filter_map" => Gem::Version.new("2.7"), # Enumerable#filter_map
    ".then"       => Gem::Version.new("2.6")  # Kernel#then
  }.freeze

  LIB = File.expand_path("../lib", __dir__)

  def test_declares_a_minimum_version
    assert defined?(RunarCompiler::MINIMUM_RUBY_VERSION),
           "RunarCompiler must declare MINIMUM_RUBY_VERSION so the failure on an " \
           "older interpreter names a version instead of a missing method"
  end

  def test_declared_floor_covers_every_versioned_feature_in_use
    declared = Gem::Version.new(RunarCompiler::MINIMUM_RUBY_VERSION)
    sources = Dir.glob(File.join(LIB, "**", "*.rb"))
    refute_empty sources, "found no Ruby sources to scan — this guard would be vacuous"

    VERSIONED_FEATURES.each do |call, needed|
      users = sources.select { |f| File.read(f).include?(call) }
      next if users.empty?

      assert declared >= needed,
             "#{call} requires Ruby #{needed} and is used in " \
             "#{users.map { |f| f.sub("#{LIB}/", '') }.first(3).join(', ')}, " \
             "but MINIMUM_RUBY_VERSION is #{declared}"
    end
  end

  def test_the_running_interpreter_satisfies_the_declared_floor
    assert Gem::Version.new(RUBY_VERSION) >= Gem::Version.new(RunarCompiler::MINIMUM_RUBY_VERSION),
           "this interpreter (#{RUBY_VERSION}) is below the declared floor"
  end
end
