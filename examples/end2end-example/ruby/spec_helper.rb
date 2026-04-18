# frozen_string_literal: true

require 'runar'
require 'shellwords'

PROJECT_ROOT = File.expand_path('../..', __dir__).freeze

# Compile a .runar.rb contract through the native Ruby compiler.
#
# @param rel_path [String] path relative to examples/end2end-example/ruby/
# @return [String] compiled artifact JSON
# @raise [RuntimeError] if compilation fails
def compile_contract(rel_path)
  abs_path = File.expand_path(rel_path, __dir__)
  compiler_bin = File.join(PROJECT_ROOT, 'compilers', 'ruby', 'bin', 'runar-compiler-ruby')

  output = `ruby #{Shellwords.escape(compiler_bin)} --source #{Shellwords.escape(abs_path)} 2>&1`
  status = Process.last_status
  raise "Compilation failed for #{rel_path}:\n#{output}" unless status&.success?

  output
end
