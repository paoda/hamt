# Hash Array Mapped Trie

A barebones implementation of [this paper](https://infoscience.epfl.ch/record/64398) by Phil Bagwell. 

### Usage

As an example: 
```zig
const std = @import("std");
const expectEqual = std.testing.expectEqual;
const HashArrayMappedTrie = @import("hamt").HashArrayMappedTrie;

const StringTrie = HashArrayMappedTrie([]const u8, void, StringContext);

const StringContext = struct {
    // Note: This definition is *required*
    // TODO: I could just grab the @typeInfo(HashFn).Fn.return_type right?
    pub const Digest = u64;

    pub inline fn hash(key: []const u8) Digest {
        return std.hash.Wyhash.hash(0, key);
    }

    pub inline fn eql(left: []const u8, right: []const u8) bool {
        return std.mem.eql(u8, left, right);
    }
};

test {
    const Pair = StringTrie.Pair;
    const allocator = std.testing.allocator;

    var trie = StringTrie.init();
    defer trie.deinit(allocator);

    try trie.insert(allocator, "hello", {});

    try expectEqual(@as(?Pair, .{ .key = "hello", .value = {} }), trie.search("hello"));
    try expectEqual(@as(?Pair, null), trie.search("world"));
}
```

### Building 

Build in release mode with `zig build -Doptimzie=ReleaseSafe`;

