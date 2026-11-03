# frozen_string_literal: true

require_relative 'types'

module Runar
  module Analyzer
    # Opcode concerns (spec §10).
    module OpcodeConcerns
      # Format n/1024 as JS (n/1024).toFixed(1).
      #
      # Per ECMA-262, toFixed picks the integer k for which k/10 - value
      # is closest to zero, and on an exact tie picks the LARGER k -
      # round-half-up (ties away from zero for our non-negative n), not
      # IEEE-754 round-half-to-even. Verified live:
      # node -e "console.log((500992/1024).toFixed(1))" prints "489.3",
      # where round-half-to-even would give "489.2".
      # spec §5.1: k = round_half_up(n * 10 / 1024) / 10
      def self.format_kb(n)
        # Compute scaled = n*10/1024 with round-half-up on exact ties.
        numer = n * 10
        denom = 1024
        q, r = numer.divmod(denom)
        twice = r * 2
        q += 1 if twice >= denom
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
