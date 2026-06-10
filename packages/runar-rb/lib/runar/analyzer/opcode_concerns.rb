# frozen_string_literal: true

require_relative 'types'

module Runar
  module Analyzer
    # Opcode concerns (spec §10).
    module OpcodeConcerns
      # Format n/1024 as JS (n/1024).toFixed(1).
      # spec §5.1: k = round_half_to_even(n * 10 / 1024) / 10
      # Use Ruby's BigDecimal-equivalent via integer arithmetic with
      # banker's rounding.
      def self.format_kb(n)
        # Compute scaled = n*10/1024 with banker's (half-to-even) rounding.
        numer = n * 10
        denom = 1024
        q, r = numer.divmod(denom)
        twice = r * 2
        if twice > denom
          q += 1
        elsif twice == denom
          # Round half to even.
          q += 1 if q.odd?
        end
        # q is the integer tenths. Render as "<int>.<digit>".
        whole = q / 10
        tenth = q % 10
        "#{whole}.#{tenth}"
      end

      def self.analyze(ops, script_size_bytes)
        findings = []

        # LARGE_SCRIPT (once).
        if script_size_bytes > LARGE_SCRIPT_THRESHOLD
          kb = format_kb(script_size_bytes)
          findings << {
            severity: 'info',
            code: 'LARGE_SCRIPT',
            message: "Script is #{script_size_bytes} bytes (#{kb} KB) — consider if this is intentional"
          }
        end

        ops.each do |op|
          # CODESEPARATOR_PRESENT
          if op[:opcode] == 0xab
            findings << {
              severity: 'info',
              code: 'CODESEPARATOR_PRESENT',
              message: 'OP_CODESEPARATOR found — expected for stateful contracts, unusual otherwise',
              offset: op[:offset],
              opcode: 'OP_CODESEPARATOR'
            }
          end

          # INEFFICIENT_PUSH
          enc = op[:push_encoding]
          next unless enc
          dl = op[:data_length]
          case enc
          when :pushdata1
            if dl <= 75
              findings << {
                severity: 'info',
                code: 'INEFFICIENT_PUSH',
                message: "OP_PUSHDATA1 used for #{dl}-byte data — direct push (opcode 0x#{format('%02x', dl)}) would be more efficient",
                offset: op[:offset],
                opcode: op[:name]
              }
            end
          when :pushdata2
            if dl <= 255
              findings << {
                severity: 'info',
                code: 'INEFFICIENT_PUSH',
                message: "OP_PUSHDATA2 used for #{dl}-byte data — OP_PUSHDATA1 would be more efficient",
                offset: op[:offset],
                opcode: op[:name]
              }
            end
          when :pushdata4
            if dl <= 65_535
              findings << {
                severity: 'info',
                code: 'INEFFICIENT_PUSH',
                message: "OP_PUSHDATA4 used for #{dl}-byte data — OP_PUSHDATA2 would be more efficient",
                offset: op[:offset],
                opcode: op[:name]
              }
            end
          end
        end

        findings
      end
    end
  end
end
