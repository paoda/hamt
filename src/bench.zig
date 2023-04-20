const std = @import("std");
const HashArrayMappedTrie = @import("hamt").HashArrayMappedTrie;

const StringContext = struct {
    pub const Digest = u64;

    pub fn hash(input: []const u8) Digest {
        return std.hash.Wyhash.hash(0, input);
    }

    pub fn eql(left: []const u8, right: []const u8) bool {
        return std.mem.eql(u8, left, right);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!gpa.deinit());

    const allocator = gpa.allocator();

    const keys = try allocator.alloc([32]u8, 10);
    defer allocator.free(keys);

    var rand = std.rand.DefaultPrng.init(0);
    for (keys) |*key| rand.fill(key);

    var trie = HashArrayMappedTrie([]const u8, void, StringContext).init();
    defer trie.deinit(allocator);

    for (keys) |*key| {
        try trie.insert(allocator, key, {});
    }

    var timer = try std.time.Timer.start();
    for (keys) |*key| {
        _ = trie.search(key);
    }

    std.debug.print("{}ns\n", .{timer.read()});
}
