# frozen_string_literal: true

require 'spec_helper'
require 'tmpdir'
require_relative '../support/ruby_compiler_cli'

# N-477: the issue100/106/123 specs used to turn a FAILED compile into
# a skip. This proves the shared helper they now
# use fails on a failing compile, skips (nil) only when the CLI is absent, and
# fails on absence under RUNAR_INTEGRATION_STRICT=1.
# It does not prove the real Ruby compiler compiles any particular contract;
# issue100/106/123 specs exercise that.
RSpec.describe RubyCompilerCli do
  def with_fake_cli(body)
    Dir.mktmpdir do |dir|
      cli = File.join(dir, 'fake-cli')
      File.write(cli, body)
      src = File.join(dir, 'X.runar.ts')
      File.write(src, '')
      yield cli, src
    end
  end

  def with_env(value)
    old = ENV.fetch('RUNAR_INTEGRATION_STRICT', nil)
    ENV['RUNAR_INTEGRATION_STRICT'] = value
    yield
  ensure
    ENV['RUNAR_INTEGRATION_STRICT'] = old
  end

  it 'raises (does not return nil/skip) when the CLI exists but exits non-zero' do
    with_fake_cli("warn 'boom'\nexit 3\n") do |cli, src|
      with_env(nil) do
        expect { described_class.compile(src, cli: cli) }
          .to raise_error(RubyCompilerCli::CompileFailed, /exit 3.*boom/m)
      end
    end
  end

  it 'returns stdout when the compile succeeds' do
    with_fake_cli("puts '{\"ok\":1}'\n") do |cli, src|
      expect(described_class.compile(src, cli: cli)).to eq("{\"ok\":1}\n")
    end
  end

  it 'returns nil when the CLI is genuinely absent and strict mode is off' do
    with_env(nil) do
      expect(described_class.compile('/nonexistent/X.runar.ts', cli: '/nonexistent/cli')).to be_nil
    end
  end

  it 'raises when the CLI is absent under RUNAR_INTEGRATION_STRICT=1' do
    with_env('1') do
      expect { described_class.compile('/nonexistent/X.runar.ts', cli: '/nonexistent/cli') }
        .to raise_error(RubyCompilerCli::CompileFailed, /not found/)
    end
  end
end
