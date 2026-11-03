# frozen_string_literal: true

require_relative "test_helper"
require "open3"
require "tmpdir"
require "fileutils"

# F-334 (CL-GAP-053): compilers/ruby shipped no gemspec, Gemfile, or
# lockfile — the only tier with an undeclared, unpinned dependency surface.
# Every other tier pins its dev/test toolchain (go.mod/go.sum, Cargo.toml/
# Cargo.lock, pyproject.toml, build.zig.zon, build.gradle); this tier's
# `rake test` ran rake/minitest/ostruct from whatever the interpreter
# happened to have installed, with no record of which versions.
#
# This drives the real `bundle` CLI in frozen mode (`BUNDLE_FROZEN=true`,
# the same guarantee `bundle install --deployment` gives: refuse rather than
# silently rewrite the lockfile) against scratch copies of just the Gemfile
# + Gemfile.lock pair — bundler needs nothing else from the directory, so
# the destructive scenarios (missing file, drifted manifest) never touch
# the real files other tests and agents rely on.
#
# Proves: the Gemfile/Gemfile.lock pair this tier ships is self-consistent
# under frozen `bundle install`, and that removing the manifest, removing
# the lockfile, or adding a gem to the manifest without updating the
# lockfile is caught (non-zero exit) rather than silently passing or
# silently rewriting the lockfile out from under frozen mode.
# Does not prove: that the pinned gem versions remain installable forever,
# or that every Ruby patch release / bundler version resolves byte-identical
# output to the one that generated this lockfile — only that this specific
# Gemfile/Gemfile.lock pair is internally consistent, the same thing a
# deploy-time `bundle install --deployment` would check.
class TestDependencyManifest < Minitest::Test
  RUBY_DIR = File.expand_path("..", __dir__)
  GEMFILE = File.join(RUBY_DIR, "Gemfile")
  LOCKFILE = File.join(RUBY_DIR, "Gemfile.lock")

  def test_gemfile_exists
    assert File.exist?(GEMFILE),
           "compilers/ruby/Gemfile is missing — the dependency surface is undeclared"
  end

  def test_lockfile_exists
    assert File.exist?(LOCKFILE),
           "compilers/ruby/Gemfile.lock is missing — the dependency surface is unpinned"
  end

  def test_checked_in_manifest_and_lockfile_are_consistent
    skip "no Gemfile to check" unless File.exist?(GEMFILE)
    skip "no Gemfile.lock to check" unless File.exist?(LOCKFILE)

    status, out = in_scratch_copy(gemfile: true, lockfile: true) { |gemfile| frozen_bundle_install(gemfile) }
    assert status.success?,
           "bundle install --frozen failed against the checked-in Gemfile/Gemfile.lock:\n#{out}"
  end

  def test_catches_a_missing_gemfile
    status, out = in_scratch_copy(gemfile: false, lockfile: true) { |gemfile| frozen_bundle_install(gemfile) }
    refute status.success?,
           "bundle install --frozen passed with no Gemfile present:\n#{out}"
  end

  def test_catches_a_missing_lockfile
    status, out = in_scratch_copy(gemfile: true, lockfile: false) { |gemfile| frozen_bundle_install(gemfile) }
    refute status.success?,
           "bundle install --frozen passed with no Gemfile.lock present:\n#{out}"
  end

  def test_catches_a_gemfile_dependency_absent_from_the_lockfile
    status, out = in_scratch_copy(gemfile: true, lockfile: true) do |gemfile|
      File.open(gemfile, "a") { |f| f.puts "gem 'json', '2.7.1'" }
      frozen_bundle_install(gemfile)
    end
    refute status.success?,
           "bundle install --frozen passed with a Gemfile gem absent from the lockfile:\n#{out}"
  end

  private

  # Copies the real Gemfile/Gemfile.lock (whichever `gemfile:`/`lockfile:`
  # select) into a scratch directory and yields the scratch Gemfile's path.
  # Bundler always looks for the lockfile at "<gemfile path>.lock", so a
  # missing copy there is exactly "no lockfile present" to the real CLI.
  def in_scratch_copy(gemfile:, lockfile:)
    Dir.mktmpdir("f334-dependency-manifest-") do |dir|
      scratch_gemfile = File.join(dir, "Gemfile")
      FileUtils.cp(GEMFILE, scratch_gemfile) if gemfile
      FileUtils.cp(LOCKFILE, "#{scratch_gemfile}.lock") if lockfile
      yield scratch_gemfile
    end
  end

  # Runs `bundle install` against +gemfile+ with BUNDLE_FROZEN=true, which
  # refuses to add, remove, or resolve anything not already pinned in the
  # lockfile — the same check a deploy-time `bundle install --deployment`
  # performs. No network call is needed when the manifest and lockfile
  # already agree, since every gem is already resolved in the lockfile.
  #
  # When this test file itself runs under an outer `bundle exec` (e.g. `bundle
  # exec rake test`), bundler exports BUNDLE_LOCKFILE pointing at the REAL
  # compilers/ruby/Gemfile.lock into every child process's environment —
  # overriding the usual "<gemfile>.lock" convention regardless of
  # BUNDLE_GEMFILE, so a naive child would silently check the wrong lockfile
  # and every scratch "missing/inconsistent lockfile" scenario below would
  # pass against the real one instead of failing. Clearing it (and the other
  # BUNDLE_*/RUBYOPT vars bundler injects for its own subprocesses) makes
  # this check the scratch Gemfile/Gemfile.lock pair, not the ambient one.
  def frozen_bundle_install(gemfile)
    env = {
      "BUNDLE_GEMFILE" => gemfile,
      "BUNDLE_FROZEN" => "true",
      "BUNDLE_LOCKFILE" => nil,
      "BUNDLE_BIN_PATH" => nil,
      "BUNDLE_APP_CONFIG" => nil,
      "RUBYOPT" => nil
    }
    out, status = Open3.capture2e(env, "bundle", "install", "--quiet", chdir: File.dirname(gemfile))
    [status, out]
  end
end
