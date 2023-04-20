const std = @import("std");

const Allocator = std.mem.Allocator;
const Log2Int = std.math.Log2Int;

/// Hash Array Mapped Trie
/// https://idea.popcount.org/2012-07-25-introduction-to-hamt/
pub fn HashArrayMappedTrie(comptime K: type, comptime V: type, comptime Context: type) type {
    // zig fmt: off
    comptime { verify(K, Context); }
    // zig fmt: on

    return struct {
        const Self = @This();

        const Digest = Context.Digest; // as in Hash Code or Hash Digest
        const table_size = @typeInfo(Digest).Int.bits;
        const t = @intCast(Log2Int(Digest), @typeInfo(Log2Int(Digest)).Int.bits);

        root: [table_size]?*Node,

        const Node = union(enum) { kv: Pair, table: Table };
        const Table = struct { map: Digest = 0, base: [*]Node };
        pub const Pair = struct { key: K, value: V };

        pub fn init() Self {
            return Self{ .root = [_]?*Node{null} ** table_size };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            for (self.root) |maybe_node| {
                const node = maybe_node orelse continue;

                _deinit(allocator, node);
                allocator.destroy(node);
            }
        }

        fn _deinit(allocator: Allocator, node: *Node) void {
            switch (node.*) {
                .kv => |_| return, // will be deallocated by caller
                .table => |table| {
                    const amt_ptr = table.base[0..@popCount(table.map)]; // Array Mapped Table

                    for (amt_ptr) |*sub_node| {
                        if (sub_node.* == .table) {
                            _deinit(allocator, sub_node);
                        }
                    }

                    allocator.free(amt_ptr);
                },
            }
        }

        fn tableIdx(hash: Digest, offset: u16) Log2Int(Digest) {
            const shift_amt = @intCast(Log2Int(Digest), table_size - offset);

            return @truncate(Log2Int(Digest), hash >> shift_amt);
        }

        pub fn search(self: *Self, key: K) ?Pair {
            const hash = Context.hash(key);

            // most siginificant t bits from hash
            var hash_offset: Log2Int(Digest) = t;
            var current: *Node = self.root[tableIdx(hash, hash_offset)] orelse return null;

            while (true) {
                switch (current.*) {
                    .table => |table| {
                        const mask = @as(Digest, 1) << tableIdx(hash, hash_offset);

                        if (table.map & mask != 0) {
                            const idx = @popCount(table.map & (mask - 1));
                            current = &table.base[idx];

                            hash_offset += t;
                        } else return null; // hash table entry is empty
                    },
                    .kv => |pair| {
                        if (!Context.eql(pair.key, key)) return null;
                        return pair;
                    },
                }
            }
        }

        pub fn insert(self: *Self, allocator: Allocator, key: K, value: V) !void {
            const hash = Context.hash(key);

            // most siginificant t bits from hash
            var hash_offset: Log2Int(Digest) = t;
            const root_idx = tableIdx(hash, hash_offset);

            var current: *Node = self.root[root_idx] orelse {
                // node in root table is empty, place the KV here
                const node = try allocator.create(Node);
                node.* = .{ .kv = .{ .key = key, .value = value } };

                self.root[root_idx] = node;
                return;
            };

            while (true) {
                const mask = @as(Digest, 1) << tableIdx(hash, hash_offset);

                switch (current.*) {
                    .table => |*table| {
                        if (table.map & mask == 0) {
                            // Empty
                            const old_len = @popCount(table.map);
                            const new_base = try allocator.alloc(Node, old_len + 1);
                            const new_map = table.map | mask;

                            var i: Log2Int(Digest) = 0;
                            for (0..table_size) |shift| {
                                const mask_loop = @as(Digest, 1) << @intCast(u5, shift);

                                if (new_map & mask_loop != 0) {
                                    defer i += 1;

                                    const idx = @popCount(table.map & (mask_loop - 1));
                                    const copy = if (mask == mask_loop) Node{ .kv = Pair{ .key = key, .value = value } } else table.base[idx];
                                    new_base[i] = copy;
                                }
                            }

                            allocator.free(table.base[0..old_len]);
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
                        const prev_hash = Context.hash(prev_pair.key);
                        const prev_mask = @as(Digest, 1) << tableIdx(prev_hash, hash_offset);

                        switch (std.math.order(mask, prev_mask)) {
                            .lt, .gt => {
                                // there are no collisions between the two hash subsets.
                                const pairs = try allocator.alloc(Node, 2);
                                const map = mask | prev_mask;

                                pairs[@popCount(map & (prev_mask - 1))] = .{ .kv = prev_pair };
                                pairs[@popCount(map & (mask - 1))] = .{ .kv = .{ .key = key, .value = value } };

                                current.* = .{ .table = .{ .map = map, .base = pairs.ptr } };
                                return;
                            },
                            .eq => {
                                const copied_pair = try allocator.alloc(Node, 1);
                                copied_pair[0] = .{ .kv = prev_pair };

                                current.* = .{ .table = .{ .map = mask, .base = copied_pair.ptr } };
                            },
                        }
                    },
                }
            }
        }

        pub fn print(self: *Self) !void {
            const stdout = std.io.getStdOut().writer();
            var buffered = std.io.bufferedWriter(stdout);

            const w = buffered.writer();

            for (self.root, 0..) |maybe_node, i| {
                try w.print("{:0>2}: ", .{i});

                if (maybe_node) |node| {
                    try _print(w, node, 1);
                } else {
                    try w.print("null\n", .{});
                }
            }

            try buffered.flush();
        }

        fn _print(w: anytype, node: *Node, depth: u16) !void {
            // @compileLog(@TypeOf(w));

            switch (node.*) {
                .kv => |pair| {
                    try w.print(".{{ .key = \"{s}\", .value = {} }}\n", .{ pair.key, pair.value });
                },
                .table => |table| {
                    try w.print(".{{ .map = 0x{X:0>8}, .ptr = {*} }}\n", .{ table.map, table.base });

                    for (0..@popCount(table.map)) |i| {
                        for (0..depth) |_| try w.print(" ", .{});
                        try w.print("{:0>2}: ", .{i});

                        try _print(w, &table.base[i], depth + 1);
                    }
                },
            }
        }
    };
}

pub fn verify(comptime K: type, comptime Context: type) void {
    // FIXME: Context should be able to be a pointer to a type

    switch (@typeInfo(Context)) {
        .Struct, .Union, .Enum => {},
        .Pointer => @compileError("Pointer trie contexts have yet to be implemented"),
        else => @compileError("Trie context must be a type with Digest, hash(" ++ @typeName(K) ++ ") Digest, and eql(" ++ @typeName(K) ++ ", " ++ @typeName(K) ++ ") bool"),
    }

    if (@hasDecl(Context, "Digest")) {
        const Digest = Context.Digest;
        const info = @typeInfo(Digest);

        if (info != .Int) @compileError("Context.Digest must be an integer, however it was actually " ++ @typeName(Digest));
        if (info.Int.signedness != .unsigned) @compileError("Context.Digest must be an unsigned integer, however it was actually an " ++ @typeName(Digest));
    }

    if (@hasDecl(Context, "hash")) {
        const hash = Context.hash;
        const HashFn = @TypeOf(hash);

        const info = @typeInfo(HashFn);

        if (info != .Fn) @compileError("Context.hash must be a function, however it was actually" ++ @typeName(HashFn));

        const func = info.Fn;
        if (func.params.len != 1) @compileError("Invalid Context.hash signature. Expected hash(" ++ @typeName(K) ++ "), but was actually " ++ @typeName(HashFn));

        // short-circuiting guarantees no panics..............vvv here
        if (func.params[0].type == null or func.params[0].type.? != K) {
            const type_str = if (func.params[0].type) |Param| @typeName(Param) else "null";
            @compileError("Invalid Context.hash signature. Parameter must be " ++ @typeName(K) ++ ", however it was " ++ type_str);
        }

        if (func.return_type == null or func.return_type.? != Context.Digest) {
            const type_str = if (func.return_type) |Return| @typeName(Return) else "null";

            @compileError("Invalid Context.hash signature. Return type must be " ++ @typeName(Context.Digest) ++ ", however it was " ++ type_str);
        }
    }

    if (@hasDecl(Context, "eql")) {
        const eql = Context.eql;
        const EqlFn = @TypeOf(eql);

        const info = @typeInfo(EqlFn);

        if (info != .Fn) @compileError("Context.eql must be a function, however it was actually" ++ @typeName(EqlFn));

        const func = info.Fn;
        if (func.params.len != 2) @compileError("Invalid Context.eql signature. Expected eql(" ++ @typeName(K) ++ ", " ++ @typeName(K) ++ "), but was actually " ++ @typeName(EqlFn));

        // short-circuiting guarantees no panics..............vvv here
        if (func.params[0].type == null or func.params[0].type.? != K) {
            const type_str = if (func.params[0].type) |Param| @typeName(Param) else "null";
            @compileError("Invalid Context.eql signature. First parameter must be " ++ @typeName(K) ++ ", however it was " ++ type_str);
        }

        if (func.params[1].type == null or func.params[1].type.? != K) {
            const type_str = if (func.params[1].type) |Param| @typeName(Param) else "null";
            @compileError("Invalid Context.eql signature. Second parameter must be " ++ @typeName(K) ++ ", however it was " ++ type_str);
        }

        if (func.return_type == null or func.return_type.? != bool) {
            const type_str = if (func.return_type) |Return| @typeName(Return) else "null";

            @compileError("Invalid Context.eql signature, Return type must be " ++ @typeName(bool) ++ ", however it was " ++ type_str);
        }
    }
}

const StringContext = struct {
    pub const Digest = u64;

    pub inline fn hash(key: []const u8) Digest {
        return std.hash.Wyhash.hash(0, key);
    }

    pub inline fn eql(left: []const u8, right: []const u8) bool {
        return std.mem.eql(u8, left, right);
    }
};

const StringTrie = HashArrayMappedTrie([]const u8, void, StringContext);

test "trie init" {
    _ = StringTrie.init();
}

test "init and deinit" {
    const allocator = std.testing.allocator;

    var trie = StringTrie.init();
    defer trie.deinit(allocator);
}

test "trie insert" {
    const allocator = std.testing.allocator;

    var trie = StringTrie.init();
    defer trie.deinit(allocator);

    try trie.insert(allocator, "hello", {});
    try trie.insert(allocator, "world", {});
}

test "trie search" {
    const Pair = StringTrie.Pair;
    const allocator = std.testing.allocator;

    var trie = StringTrie.init();
    defer trie.deinit(allocator);

    try std.testing.expectEqual(@as(?Pair, null), trie.search("sdvx"));

    try trie.insert(allocator, "sdvx", {});

    try std.testing.expectEqual(@as(?Pair, .{ .key = "sdvx", .value = {} }), trie.search("sdvx"));
    try std.testing.expectEqual(@as(?Pair, null), trie.search(""));

    try trie.insert(allocator, "", {});
    try std.testing.expectEqual(@as(?Pair, .{ .key = "", .value = {} }), trie.search(""));
}

test "README.md example" {
    const Pair = StringTrie.Pair;
    const allocator = std.testing.allocator;

    var trie = StringTrie.init();
    defer trie.deinit(allocator);

    try trie.insert(allocator, "hello", {});

    try std.testing.expectEqual(@as(?Pair, .{ .key = "hello", .value = {} }), trie.search("hello"));
    try std.testing.expectEqual(@as(?Pair, null), trie.search("world"));
}
