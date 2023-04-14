const std = @import("std");
const HashArrayMappedTrie = @import("HashArrayMappedTrie.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!gpa.deinit());

    const allocator = gpa.allocator();

    var trie = try HashArrayMappedTrie.init(allocator);
    defer trie.deinit();

    try trie.insert("and", {});
    try trie.insert("class", {});
    try trie.insert("else", {});
    try trie.insert("false", {});
    try trie.insert("for", {});
    try trie.insert("fun", {});
    try trie.insert("if", {});
    try trie.insert("nil", {});
    try trie.insert("or", {});
    try trie.insert("print", {});
    try trie.insert("return", {});
    try trie.insert("super", {});
    try trie.insert("this", {});
    try trie.insert("true", {});
    try trie.insert("var", {});
    try trie.insert("while", {});

    trie.walk();
}
