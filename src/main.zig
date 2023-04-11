const std = @import("std");
const HashArrayMappedTrie = @import("HashArrayMappedTrie.zig");

pub fn main() !void {
    var trie = try HashArrayMappedTrie.init(std.heap.page_allocator);
    defer trie.deinit();

    try trie.insert("hello", {});
    try trie.insert("helloworld", {});
}
