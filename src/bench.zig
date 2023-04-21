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

const StringArrayHashMap = std.array_hash_map.StringArrayHashMap(void);
const StringHashMap = std.hash_map.StringHashMap(void);

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

    var array_hash_map = StringArrayHashMap.init(allocator);
    defer array_hash_map.deinit();

    var hash_map = StringHashMap.init(allocator);
    defer hash_map.deinit();

    {
        var timer = try std.time.Timer.start();
        for (keys) |*key| {
            try trie.insert(allocator, key, {});
        }
        const insert_time = timer.lap();

        for (0..50_000) |_| {
            for (keys) |*key| {
                _ = trie.search(key);
            }
        }
        const search_time = timer.read();

        std.debug.print("Hash Array Mapped Trie:\n", .{});
        std.debug.print("Insert: {}ns\n", .{insert_time});
        std.debug.print("Search: {}ns\n", .{search_time});
    }

    std.debug.print("\n", .{});

    {
        var timer = try std.time.Timer.start();
        for (keys) |*key| {
            try hash_map.putNoClobber(key, {});
        }
        const insert_time = timer.lap();

        for (0..50_000) |_| {
            for (keys) |*key| {
                _ = hash_map.get(key);
            }
        }
        const search_time = timer.read();

        std.debug.print("std.hash_map.HashMap\n", .{});
        std.debug.print("Insert: {}ns\n", .{insert_time});
        std.debug.print("Search: {}ns\n", .{search_time});
    }

    std.debug.print("\n", .{});

    {
        var timer = try std.time.Timer.start();
        for (keys) |*key| {
            try array_hash_map.putNoClobber(key, {});
        }
        const insert_time = timer.lap();

        for (0..50_000) |_| {
            for (keys) |*key| {
                _ = array_hash_map.get(key);
            }
        }
        const search_time = timer.read();

        std.debug.print("std.array_hash_map.ArrayHashMap\n", .{});
        std.debug.print("Insert: {}ns\n", .{insert_time});
        std.debug.print("Search: {}ns\n", .{search_time});
    }
}
