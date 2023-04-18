const std = @import("std");
const HashArrayMappedTrie = @import("trie.zig").HashArrayMappedTrie;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!gpa.deinit());

    const allocator = gpa.allocator();

    var trie = HashArrayMappedTrie([]const u8, void, Context(u32)).init();
    defer trie.deinit(allocator);

    try trie.insert(allocator, "and", {});
    try trie.insert(allocator, "class", {});
    try trie.insert(allocator, "else", {});
    try trie.insert(allocator, "false", {});
    try trie.insert(allocator, "for", {});
    try trie.insert(allocator, "fun", {});
    try trie.insert(allocator, "if", {});
    try trie.insert(allocator, "nil", {});
    try trie.insert(allocator, "or", {});
    try trie.insert(allocator, "print", {});
    try trie.insert(allocator, "return", {});
    try trie.insert(allocator, "super", {});
    try trie.insert(allocator, "this", {});
    try trie.insert(allocator, "true", {});
    try trie.insert(allocator, "var", {});
    try trie.insert(allocator, "while", {});

    try trie.print();
}

pub fn Context(comptime HashCode: type) type {
    const Log2Int = std.math.Log2Int;

    return struct {
        pub const Digest = HashCode;

        pub inline fn hash(key: []const u8) Digest {
            // the MSB will represent 'z'
            const offset = @typeInfo(Digest).Int.bits - 26;

            var result: Digest = 0;
            for (key) |c| result |= @as(Digest, 1) << @intCast(Log2Int(Digest), offset + c - 'a');

            return result;
        }

        pub inline fn eql(left: []const u8, right: []const u8) bool {
            return std.mem.eql(u8, left, right);
        }
    };
}
