# frozen_string_literal: true

require 'open3'

# Shared driver for specs that compile a contract through the Ruby compiler CLI
# (compilers/ruby/bin/runar-compiler-ruby).
#
# Contract (N-477):
#   * CLI genuinely absent (entrypoint file not found) -> returns nil so the
#     caller can `skip`; raises instead when RUNAR_INTEGRATION_STRICT=1 (CI), so
#     an absent compiler can never turn the run green.
#   * CLI present but the compile fails (non-zero exit) -> raises. A compiler
#     regression must fail the spec, never degrade to a skip.
module RubyCompilerCli
  class CompileFailed < StandardError; end

  DEFAULT_CLI = File.join(File.expand_path('../../../..', __dir__),
                          'compilers', 'ruby', 'bin', 'runar-compiler-ruby').freeze

  def self.strict?
    ENV['RUNAR_INTEGRATION_STRICT'] == '1'
  end

  # Returns the compiler's stdout (artifact JSON), or nil when the CLI is absent
  # and strict mode is off.
  def self.compile(src_path, cli: DEFAULT_CLI)
    unless File.exist?(cli)
      return nil unless strict?

      raise CompileFailed, "Ruby compiler CLI not found at #{cli} (RUNAR_INTEGRATION_STRICT=1)"
    end

    out, err, status = Open3.capture3('ruby', cli, '--source', src_path)
    return out if status.success?

    raise CompileFailed, "Ruby compiler CLI failed (exit #{status.exitstatus}) on #{src_path}:\n#{err}#{out}"
  end
end
