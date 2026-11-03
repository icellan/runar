# frozen_string_literal: true

# N-317: one hostile UTXO script must not take TokenWallet#get_utxos down, and
# matches_artifact must agree with the TS SDK on every malformed shape.
#
# Replays the shared cross-tier vector
# conformance/sdk-matches-artifact/hostile.json (also replayed by the TS, Go,
# Rust, Python, Zig and Java SDKs): odd-length and non-hex scripts, truncated
# OP_PUSHDATA1/2/4, OP_PUSHDATA4 lengths with the high bit set, a push running
# past the slot, empty and short scripts and ~1 MiB scripts, beside SDK-built
# genuine instances.
#
# Proves: matches_artifact gives exactly the fixture's outcome per vector
# (true / false / MalformedScriptError; any other exception fails it);
# get_utxos keeps exactly the genuine instances for a stateful and a stateless
# artifact and never raises; the replay stays inside a process-CPU budget
# (CLOCK_PROCESS_CPUTIME_ID, polled by a watchdog thread that interrupts the
# replay at the budget, so a hang fails instead of running forever).
# Does NOT prove: on-chain spendability of the kept UTXOs, artifact shapes
# beyond the fixture's two, or anything about a forged codeSepIndex element
# (N-318).

require 'spec_helper'
require 'json'
require 'runar/sdk'

N317_FIXTURE = JSON.parse(
  File.read(File.expand_path('../../../../../conformance/sdk-matches-artifact/hostile.json', __FILE__), encoding: 'UTF-8')
)
# Measured: well under a second of CPU after the fix.
N317_CPU_BUDGET_SECS = 20.0

# Exception (not StandardError) so no `rescue StandardError` under test swallows it.
class N317OverBudget < Exception; end # rubocop:disable Lint/InheritException

RSpec.describe 'N-317: hostile UTXO scripts (shared vector)' do
  def n317_script(c)
    c['prefix'] + (c['repeat'] || '') * (c['count'] || 0) + (c['suffix'] || '')
  end

  def n317_replay
    artifacts = N317_FIXTURE['artifacts'].transform_values { |a| Runar::SDK::RunarArtifact.from_hash(a) }
    cases = N317_FIXTURE['cases']
    diffs = []
    cases.each do |c|
      got = begin
        Runar::SDK::ScriptUtils.matches_artifact(artifacts[c['artifact']], n317_script(c)) ? 'match' : 'no_match'
      rescue Runar::SDK::MalformedScriptError
        'malformed'
      rescue StandardError => e
        "error:#{e.class}: #{e.message}"
      end
      diffs << "#{c['name']}: want #{c['matches']}, got #{got}" unless got == c['matches']
    end
    artifacts.each do |name, artifact|
      provider = Runar::SDK::MockProvider.new
      signer = Runar::SDK::MockSigner.new
      want = []
      cases.each_with_index do |c, i|
        next if c['artifact'] != name || c['wallet'].nil?

        txid = format('%02x', i) * 32
        provider.add_utxo(signer.get_address,
                          Runar::SDK::Utxo.new(txid: txid, output_index: 0, satoshis: 1000, script: n317_script(c)))
        want << txid if c['wallet']
      end
      begin
        kept = Runar::SDK::TokenWallet.new(artifact, provider, signer).get_utxos.map(&:txid)
        diffs << "get_utxos (#{name}): want #{want}, got #{kept}" unless kept == want
      rescue StandardError => e
        diffs << "get_utxos (#{name}) raised #{e.class}: #{e.message}"
      end
    end
    diffs
  end

  it 'rejects every hostile script without aborting the listing, inside the CPU budget' do
    start = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
    main = Thread.current
    watchdog = Thread.new do
      loop do
        sleep 0.1
        used = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - start
        next if used < N317_CPU_BUDGET_SECS

        main.raise(N317OverBudget, "replay exceeded #{N317_CPU_BUDGET_SECS} s of CPU")
        break
      end
    end
    begin
      diffs = n317_replay
    ensure
      watchdog.kill
    end
    expect(Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - start).to be < N317_CPU_BUDGET_SECS
    expect(diffs).to eq([]), diffs.join("\n")
  end
end
