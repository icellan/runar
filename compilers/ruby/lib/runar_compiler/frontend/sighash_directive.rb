# frozen_string_literal: true

# `@sighash` directive parsing (issue #123).
#
# A public method may carry a `/** @sighash <FLAGS> */` comment directive that
# declares which BIP-143 sighash type its auto-injected covenant (and the
# SDK-built preimage) commits to. `<FLAGS>` is a `|`-separated set of SigHash
# names, e.g. `SINGLE|FORKID`, `ALL|ANYONECANPAY|FORKID`, `NONE|FORKID`.
#
# The default (no directive) is `ALL|FORKID` (0x41) — byte-identical to the
# historically-pinned mode, so existing fixtures see ZERO change.
#
# Direct port of packages/runar-compiler/src/passes/sighash-directive.ts. The
# parser owns *detection* of the directive comment; this module owns the *flag
# grammar* (name -> value, combo validity).

require "set"

module RunarCompiler
  module Frontend
    module SighashDirective
      module_function

      # Numeric value of each sighash flag name.
      FLAG_VALUES = {
        "ALL"          => 0x01,
        "NONE"         => 0x02,
        "SINGLE"       => 0x03,
        "FORKID"       => 0x40,
        "ANYONECANPAY" => 0x80,
      }.freeze

      # The base-type names. Exactly one MUST appear in a directive.
      BASE_TYPE_NAMES = %w[ALL NONE SINGLE].to_set.freeze

      # SIGHASH_ALL | SIGHASH_FORKID — the default when no directive is present.
      SIGHASH_DEFAULT = 0x41

      # Base-type mask. `sig_hash_type & BASE_TYPE_MASK` recovers 1/2/3 (ALL/
      # NONE/SINGLE) after the FORKID/ANYONECANPAY high bits are stripped.
      BASE_TYPE_MASK   = 0x1f
      BASE_ALL         = 0x01
      BASE_NONE        = 0x02
      BASE_SINGLE      = 0x03
      FLAG_FORKID      = 0x40
      FLAG_ANYONECANPAY = 0x80

      # Shared diagnostics (F-039) — identical text in all seven tiers. A marker
      # that is present but not followed by a well-formed flag list, or a second
      # marker on the same method, is a compile error, never a silent fall-back
      # to the default ALL|FORKID mode.
      SIGHASH_MALFORMED_ERROR = "@sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a " \
                                "|-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)"
      SIGHASH_MULTIPLE_ERROR = "@sighash: more than one @sighash directive on this method; declare exactly one"

      SIGHASH_MARKER = "@sighash"

      # Parse the flag list of an `@sighash` directive.
      #
      # `flags_text` is the raw text following `@sighash` (e.g. `"SINGLE|FORKID"`).
      #
      # Validation (security-relevant — a mis-declared mode is an exploit class):
      #   - every name must be a known flag (reject typos like `FORKD`)
      #   - EXACTLY ONE base type (ALL/NONE/SINGLE) — reject zero, and reject
      #     nonsensical combos such as `ALL|NONE`. Checked on NAMES, not on the
      #     OR-ed numeric value, because `ALL|NONE` (0x01|0x02) collides with the
      #     numeric value of SINGLE (0x03) — a silent, dangerous aliasing that a
      #     purely numeric check would miss.
      #   - reject a duplicated flag name (signals a copy/paste error).
      #   - FORKID is mandatory on BSV (the whole OP_PUSH_TX / BIP-143 preimage
      #     machinery is FORKID-only, so a FORKID-less flag set deploys to brick).
      #
      # @return [Hash] {value: Integer} on success, or {error: String} on failure
      def parse_sighash_flags(flags_text)
        raw = flags_text.strip
        return { error: "@sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)" } if raw.empty?

        names = raw.split("|").map(&:strip)
        seen = {}
        base_types = []
        value = 0

        names.each do |name|
          return { error: "@sighash directive has an empty flag in \"#{raw}\"" } if name.empty?

          unless FLAG_VALUES.key?(name)
            return { error: "@sighash: unknown flag \"#{name}\" (valid: ALL, NONE, SINGLE, FORKID, ANYONECANPAY)" }
          end
          return { error: "@sighash: duplicate flag \"#{name}\" in \"#{raw}\"" } if seen[name]

          seen[name] = true
          base_types << name if BASE_TYPE_NAMES.include?(name)
          value |= FLAG_VALUES[name]
        end

        if base_types.empty?
          return { error: "@sighash: must specify exactly one base type (ALL, NONE, or SINGLE); got \"#{raw}\"" }
        end
        if base_types.length > 1
          return { error: "@sighash: cannot combine base types (#{base_types.join('|')}) — pick exactly one of ALL/NONE/SINGLE" }
        end

        # FORKID is mandatory on BSV: the entire OP_PUSH_TX / BIP-143 preimage
        # machinery is FORKID-only, so a FORKID-less flag set deploys a covenant
        # whose derived signature can never verify (deploy-to-brick). Reject it
        # up front rather than let a spendable-looking script ship.
        if (value & FLAG_VALUES["FORKID"]).zero?
          return { error: "@sighash: FORKID is mandatory on BSV; write e.g. @sighash #{base_types[0]}|FORKID (got \"#{raw}\")" }
        end

        { value: value }
      end

      # Extract and parse an `@sighash` directive from a method's leading-comment
      # text (all of its leading comments, concatenated). Returns nil only when
      # no `@sighash` marker is present, otherwise the parse result ({value:} or
      # {error:}). Mirrors the TS reference.
      #
      # A marker is `@sighash` followed by an ASCII word boundary, so
      # `@sighashType` (or `@sighashSINGLE`) is prose, not a directive. Once a
      # marker is present (fail-closed, F-039): more than one marker is
      # SIGHASH_MULTIPLE_ERROR; the segment after the marker, up to `*/`, a
      # newline, CR or the end, must be empty, or start with a space/tab and
      # contain only [A-Za-z0-9_|], spaces and tabs, else SIGHASH_MALFORMED_ERROR;
      # the flag list itself is then validated by parse_sighash_flags.
      def extract_sighash_directive(comment_text)
        markers = []
        i = comment_text.index(SIGHASH_MARKER)
        until i.nil?
          nxt = comment_text[i + SIGHASH_MARKER.length]
          markers << i if nxt.nil? || !nxt.match?(/\A[A-Za-z0-9_]\z/)
          i = comment_text.index(SIGHASH_MARKER, i + 1)
        end
        return nil if markers.empty?
        return { error: SIGHASH_MULTIPLE_ERROR } if markers.length > 1

        after = comment_text[(markers[0] + SIGHASH_MARKER.length)..]
        end_idx = after.length
        after.each_char.with_index do |c, j|
          if c == "\n" || c == "\r" || (c == "*" && after[j + 1] == "/")
            end_idx = j
            break
          end
        end
        seg = after[0, end_idx]
        return { error: SIGHASH_MALFORMED_ERROR } unless seg.empty? || seg.match?(/\A[ \t][A-Za-z0-9_| \t]*\z/)

        parse_sighash_flags(seg)
      end

      # Human-readable rendering of a sighash value (for diagnostics).
      def describe_sighash(value)
        parts = []
        base = value & BASE_TYPE_MASK
        parts << case base
                 when BASE_ALL    then "ALL"
                 when BASE_NONE   then "NONE"
                 when BASE_SINGLE then "SINGLE"
                 else "0x#{base.to_s(16)}"
                 end
        parts << "ANYONECANPAY" if (value & FLAG_ANYONECANPAY) != 0
        parts << "FORKID" if (value & FLAG_FORKID) != 0
        parts.join("|")
      end
    end
  end
end
