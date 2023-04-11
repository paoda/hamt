//! Hash Array Mapped Trie
//! https://idea.popcount.org/2012-07-25-introduction-to-hamt/
const std = @import("std");
// const Token = @import("Token.zig");

const Allocator = std.mem.Allocator;
const HashArrayMappedTrie = @This();

const t = 5;
const table_size = std.math.powi(u32, 2, t) catch unreachable;

root: [table_size]?*Node,
allocator: Allocator,

const Node = union(enum) { kv: Pair, table: Table };
const Pair = struct { key: []const u8, value: void };
const Table = struct { map: u32 = 0, base: [*]Node };

pub fn init(allocator: Allocator) !HashArrayMappedTrie {
    return .{
        .root = [_]?*Node{null} ** table_size,
        .allocator = allocator,
    };
}

pub fn deinit(self: *HashArrayMappedTrie) void {
    for (self.root) |node| {
        if (node == null) continue;

        deinitRecurse(self.allocator, node.?);
    }
}

fn deinitRecurse(allocator: Allocator, node: *Node) void {
    switch (node.*) {
        .kv => allocator.destroy(node),
        else => {},
    }
}

fn amtIdx(comptime T: type, bitset: T, offset: u16) std.math.Log2Int(T) {
    const L2I = std.math.Log2Int(T);

    const shift_amt = @intCast(L2I, @typeInfo(T).Int.bits - offset);
    return @truncate(L2I, bitset >> shift_amt);
}

pub fn search(self: *HashArrayMappedTrie, key: []const u8) ?Pair {
    const bitset = hash(key);

    // most siginificant t bits from hash
    var hash_offset: u5 = t;
    var current: *Node = self.root[amtIdx(u32, bitset, hash_offset)] orelse return null;

    while (true) {
        switch (current.*) {
            .table => |table| {
                hash_offset += t;

                const mask = @as(u32, 1) << amtIdx(u32, bitset, hash_offset);

                if (table.map & mask != 0) {
                    const idx = @popCount(table.map & (mask - 1));

                    current = &table.base[idx];
                } else return null; // hash table entry is empty
            },
            .kv => |pair| {
                if (!std.mem.eql(u8, pair.key, key)) return null;
                return pair;
            },
        }
    }
}

pub fn insert(self: *HashArrayMappedTrie, comptime key: []const u8, value: void) !void {
    const bitset = hash(key);

    // most siginificant t bits from hash
    var hash_offset: u5 = t;
    const root_idx = amtIdx(u32, bitset, hash_offset);

    var current: *Node = self.root[root_idx] orelse {
        // node in root table is empty, place the KV here
        const node = try self.allocator.create(Node);
        node.* = .{ .kv = .{ .key = key, .value = value } };

        self.root[root_idx] = node;
        return;
    };

    while (true) {
        const mask = @as(u32, 1) << amtIdx(u32, bitset, hash_offset);

        switch (current.*) {
            .table => |*table| {
                if (table.map & mask == 0) {
                    // Empty
                    const old_len = @popCount(table.map);
                    const new_base = try self.allocator.alloc(Node, old_len + 1);
                    const new_map = table.map | mask;

                    var i: u5 = 0;
                    for (0..@typeInfo(u32).Int.bits) |shift| {
                        const mask_loop = @as(u32, 1) << @intCast(u5, shift);

                        if (new_map & mask_loop != 0) {
                            defer i += 1;

                            const idx = @popCount(table.map & (mask_loop - 1));
                            const copy = if (mask == mask_loop) Node{ .kv = Pair{ .key = key, .value = value } } else table.base[idx];
                            new_base[i] = copy;
                        }
                    }

                    self.allocator.free(table.base[0..old_len]);
                    table.base = new_base.ptr;
                    table.map = new_map;

                    return; // inserted an elemnt into the Trie
                } else {
                    // Found an entry in the array, continue loop (?)
                    const idx = @popCount(table.map & (mask - 1));
                    current = &table.base[idx];

                    hash_offset += t; // Go one layer deper
                }
            },
            .kv => |prev_pair| {
                const prev_bitset = hash(prev_pair.key);
                const prev_mask = @as(u32, 1) << amtIdx(u32, prev_bitset, hash_offset);

                const table = switch (std.math.order(mask, prev_mask)) {
                    .lt => blk: {
                        // there are no collisions between the two hash subsets.
                        const pairs = try self.allocator.alloc(Node, 2);
                        pairs[0] = .{ .kv = .{ .key = key, .value = value } };
                        pairs[1] = .{ .kv = prev_pair };

                        break :blk .{ .table = .{ .map = mask | prev_mask, .base = pairs.ptr } };
                    },
                    .gt => blk: {
                        // there are no collisions between the two hash subsets.
                        const pairs = try self.allocator.alloc(Node, 2);
                        pairs[0] = .{ .kv = prev_pair };
                        pairs[1] = .{ .kv = .{ .key = key, .value = value } };

                        break :blk .{ .table = .{ .map = mask | prev_mask, .base = pairs.ptr } };
                    },
                    .eq => blk: {
                        const copied_pair = try self.allocator.alloc(Node, 1);
                        copied_pair[0] = .{ .kv = prev_pair };

                        break :blk .{ .table = .{ .map = mask, .base = copied_pair.ptr } };
                    },
                };

                current.* = table;
            },
        }
    }
}

fn walk(node: *const Node, indent: u8) void {
    switch (node.*) {
        .kv => |pair| std.debug.print("{}: {any}\n", .{ indent, pair }),
        .table => |table| {
            const len = @popCount(table.map);

            for (0..len) |i| {
                walk(&table.base[i], indent + 1);
            }
        },
    }
}

fn hash(key: []const u8) u32 {
    var result: u32 = 0;

    // 6 because we're working with 'a' -> 'z'
    for (key) |c| result |= @as(u32, 1) << 6 + @intCast(u5, c - 'a');

    return result;
}

test "insert doesn't panic" {
    var trie = try HashArrayMappedTrie.init(std.testing.allocator);
    defer trie.deinit();

    try trie.insert("hello", {});
}

test "search doesn't panic" {
    var trie = try HashArrayMappedTrie.init(std.testing.allocator);
    defer trie.deinit();

    std.debug.assert(trie.search("hello") == null);
}

test "insert then search" {
    var trie = try HashArrayMappedTrie.init(std.heap.page_allocator);
    defer trie.deinit();

    // Basic Usage
    try trie.insert("hello", {});
    const test1 = trie.search("hello").?;
    try std.testing.expectEqual(Pair{ .key = "hello", .value = {} }, test1);

    // Collision in Root Node
    try trie.insert("helloworld", {});
    const test2 = trie.search("helloworld").?;
    try std.testing.expectEqual(Pair{ .key = "helloworld", .value = {} }, test2);
}
