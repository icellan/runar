# frozen_string_literal: true

require "set"

# N-096: the syntheticArrayChain validity rule for --ir input. Port of
# packages/runar-compiler/src/ir/synthetic-array-chain.ts: same rule, same
# order, same words (conformance/negatives/ir-synthetic-array-chain.test.ts).
#
#   1. at most MAX_DEPTH levels (the regrouper's 1024 passes are the only
#      nesting bound the pipeline has);
#   2. every level has 0 <= index < length;
#   3. level k's base is level k-1's "<base>__<index>", and the property is
#      named "<innermost base>__<innermost index>";
#   4. the leaves sharing a root are exactly one expansion: contiguous,
#      row-major from element 0, one type and one list of level lengths, and
#      complete.

module RunarCompiler
  module IR
    module SyntheticArrayChain
      # The deepest chain the regrouper's 1024-pass cap can consume.
      MAX_DEPTH = 1023

      def self.refuse(prop, detail)
        ArgumentError.new("IR validation: malformed syntheticArrayChain on property '#{prop}': #{detail}")
      end

      def self.leaf_name(root, tuple)
        root + tuple.map { |i| "__#{i}" }.join
      end

      def self.complete?(fam)
        fam[:tuple].each_with_index.all? { |i, k| i == fam[:lengths][k] - 1 }
      end

      def self.next_tuple(fam)
        t = fam[:tuple].dup
        (t.length - 1).downto(0) do |k|
          if t[k] + 1 < fam[:lengths][k]
            t[k] += 1
            return t
          end
          t[k] = 0
        end
        t
      end

      def self.expects(root, type, lengths, tuple)
        "'#{root}' expects its element '#{leaf_name(root, tuple)}' here " \
          "(type #{type}, level lengths [#{lengths.join(', ')}])"
      end

      def self.int?(v)
        v.is_a?(Integer)
      end

      def self.check_levels!(name, chain)
        if chain.length > MAX_DEPTH
          raise refuse(name, "#{chain.length} levels exceed the limit of #{MAX_DEPTH}")
        end
        chain.each_with_index do |lvl, k|
          unless lvl.is_a?(Hash) && lvl["base"].is_a?(String) && int?(lvl["index"]) && int?(lvl["length"])
            raise refuse(name, "level #{k} is not a {base: string, index: integer, length: integer} object")
          end
          index = lvl["index"]
          length = lvl["length"]
          unless index >= 0 && index < length
            raise refuse(name, "level #{k} has index #{index} and length #{length}; " \
                               "expand-fixed-arrays writes 0 <= index < length")
          end
          next unless k.positive?

          want = "#{chain[k - 1]['base']}__#{chain[k - 1]['index']}"
          unless lvl["base"] == want
            raise refuse(name, "level #{k} has base '#{lvl['base']}'; expand-fixed-arrays writes '#{want}'")
          end
        end
        inner = chain[-1]
        want = "#{inner['base']}__#{inner['index']}"
        return if name == want

        raise refuse(name, "its innermost level is element #{inner['index']} of '#{inner['base']}'; " \
                           "expand-fixed-arrays names that property '#{want}'")
      end

      # Raises the shared diagnostic for the first chain the rule refuses.
      def self.assert!(program)
        open = nil
        seen = Set.new
        close = lambda do
          if open && !complete?(open)
            raise refuse(open[:last], "'#{open[:root]}' ends here, before its element " \
                                      "'#{leaf_name(open[:root], next_tuple(open))}'")
          end
          open = nil
        end

        program.properties.each do |prop|
          chain = prop.synthetic_array_chain || []
          raise refuse(prop.name, "the chain is not an array") unless chain.is_a?(Array)

          root = chain.first.is_a?(Hash) ? chain.first["base"] : nil
          close.call if open && root != open[:root]
          next if chain.empty?

          check_levels!(prop.name, chain)
          tuple = chain.map { |l| l["index"] }
          lengths = chain.map { |l| l["length"] }

          if open
            raise refuse(prop.name, "'#{open[:root]}' already ended before this property") if complete?(open)

            want = next_tuple(open)
            if prop.type != open[:type] || lengths != open[:lengths] || tuple != want
              raise refuse(prop.name, expects(open[:root], open[:type], open[:lengths], want))
            end
            open[:tuple] = want
            open[:last] = prop.name
            next
          end

          raise refuse(prop.name, "'#{root}' already ended before this property") if seen.include?(root)

          start = Array.new(chain.length, 0)
          raise refuse(prop.name, expects(root, prop.type, lengths, start)) unless tuple == start

          seen << root
          open = { root: root, type: prop.type, lengths: lengths, tuple: tuple, last: prop.name }
        end
        close.call
      end
    end
  end
end
