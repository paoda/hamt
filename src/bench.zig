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
    const elem_count = 1000;

    const keys = try allocator.alloc([32]u8, elem_count);
    defer allocator.free(keys);

    var rand = std.rand.DefaultPrng.init(1337);
    for (keys) |*key| rand.fill(key);

    var trie = try HashArrayMappedTrie([]const u8, void, StringContext).init(allocator);
    defer trie.deinit(allocator);

    var timer = try std.time.Timer.start();
    for (keys) |*key| {
        try trie.insert(allocator, key, {});
    }
    const insert_time = timer.lap();

    for (keys) |*key| {
        _ = trie.search(key);
    }
    const search_time = timer.read();

    std.debug.print("Insert: {d:.2}ns\n", .{(@intToFloat(f32, insert_time) / elem_count) * 100.0});
    std.debug.print("Search: {d:.2}ns\n", .{(@intToFloat(f32, search_time) / elem_count) * 100.0});
}
