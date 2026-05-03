# frozen_string_literal: true

require 'runar'
require 'shellwords'

PROJECT_ROOT = File.expand_path('../../..', __dir__).freeze

# Compile a .runar.rb contract through the native Ruby compiler.
#
# @param rel_path [String] path relative to examples/end2end-example/ruby/
# @return [String] compiled artifact JSON
# @raise [RuntimeError] if compilation fails
def compile_contract(rel_path)
  abs_path = File.expand_path(rel_path, __dir__)
  compiler_bin = File.join(PROJECT_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')

  # Capture stdout (artifact JSON) and stderr (Ruby warnings) separately so
  # bundler/RubyGems warnings printed to stderr do not corrupt the artifact
  # JSON returned to the caller.
  require 'open3'
  stdout, stderr, status = Open3.capture3('ruby', compiler_bin, '--source', abs_path)
  raise "Compilation failed for #{rel_path}:\nSTDOUT:\n#{stdout}\nSTDERR:\n#{stderr}" unless status&.success?

  stdout
end
