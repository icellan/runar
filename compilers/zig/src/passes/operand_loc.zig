//! N-492: operand locations for the surface parsers other than `.runar.ts`.
//!
//! The TS reference locates a binary node's operands at the START of each
//! operand's node: its first token, except that a parenthesis wrapping the
//! WHOLE operand is unwrapped to the first token inside it (`(a + b)` starts
//! at `a`, while `(a + b) + c` starts at the outer `(`). `parse_ts.zig`
//! re-lexes from the `(` to find the matching `)`; the other eight surfaces
//! have different tokenizers, so they record each parenthesised primary here
//! instead and ask whether the operand ended exactly at its `)`.
//!
//! Tokens are matched on (line, col), which is unique per token in a file.

const std = @import("std");

/// `Token` is the parser's own token type (it needs `line` and `col`).
pub fn OperandLocs(comptime Token: type) type {
    return struct {
        const Self = @This();
        const Paren = struct { inner: Token, close: u64 };

        parens: std.AutoHashMapUnmanaged(u64, Paren) = .empty,
        /// Key of the most recently consumed token.
        last: u64 = 0,

        fn key(tok: anytype) u64 {
            return (@as(u64, tok.line) << 32) | @as(u64, tok.col);
        }

        /// Call from the parser's `bump` with the token just consumed.
        pub fn consumed(self: *Self, tok: anytype) void {
            self.last = key(tok);
        }

        /// Call after a parenthesised primary: `open` is its `(`, `inner` the
        /// first token after it, `close` its `)`.
        pub fn recordParen(self: *Self, allocator: std.mem.Allocator, open: Token, inner: Token, close: Token) void {
            self.parens.put(allocator, key(open), .{
                .inner = inner,
                .close = key(close),
            }) catch {};
        }

        /// The token where the TS reference locates the operand that began at
        /// token `start` and ends at the token just consumed.
        pub fn startOf(self: *const Self, start: Token) Token {
            var tok = start;
            while (self.parens.get(key(tok))) |p| {
                if (p.close != self.last) break;
                tok = p.inner;
            }
            return tok;
        }
    };
}
