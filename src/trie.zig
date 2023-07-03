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
        const t: Log2Int(Digest) = @intCast(@typeInfo(Log2Int(Digest).Int.bits));

        free_list: FreeList,
        root: []?*Node,

        const Node = union(enum) { kv: Pair, table: Table };
        const Table = struct { map: Digest = 0, base: [*]Node };
        pub const Pair = struct { key: K, value: V };

        /// Responsible for managing HAMT Memory
        const FreeList = struct {
            list: *[table_size]?FreeList.Node,

            // The index of the array of the linked list any given node belongs to
            // informs us of how many elements there are in the [*]Node ptr.
            const Node = struct {
                inner: [*]Self.Node,
                next: ?*FreeList.Node = null,

                pub fn deinit(self: *const FreeList.Node, allocator: Allocator, len: usize) void {
                    switch (len) {
                        0 => unreachable,
                        1 => allocator.destroy(@as(*Self.Node, @ptrCast(self.inner))),
                        else => allocator.free(self.inner[0..len]),
                    }
                }
            };

            pub fn init(allocator: Allocator) !FreeList {
                const list = try allocator.create([table_size]?FreeList.Node);
                std.mem.set(?FreeList.Node, list, null);

                return .{ .list = list };
            }

            pub fn deinit(self: *FreeList, allocator: Allocator) void {
                for (self.list, 0..) |maybe_node, i| {
                    // the nodes that exist within the array `self.list` are freed outside
                    // of this `for` loop, so if any given `maybe_node` is a linked list that is
                    // 0 or 1 elements long, there is no thing to do here.
                    const len = i + 1;

                    var current: *FreeList.Node = blk: {
                        const head = maybe_node orelse continue; // skip if list is 0 elements long

                        head.deinit(allocator, len); // while we know the head exists, free the memory it points to
                        break :blk head.next orelse continue; // skip if list is 1 element long (see above comment)
                    };

                    while (current.next) |next| {
                        const next_ptr = next; // copy the pointer 'cause we're about to deallocate it's owner

                        current.deinit(allocator, len);
                        allocator.destroy(current);

                        current = next_ptr;
                    }

                    current.deinit(allocator, len); // free the tail of the list
                    allocator.destroy(current);
                }

                allocator.destroy(self.list);
                self.* = undefined;
            }

            pub fn alloc(self: *FreeList, allocator: Allocator, comptime T: type, len: usize) ![]T {
                if (len == 0 or len > table_size) return error.unexpected_table_length;

                // If head is null, (head is self.list[len - 1]) then there was nothing in the free list
                // therefore we should use the backup allocator
                var current: *FreeList.Node = &(self.list[len - 1] orelse return try allocator.alloc(T, len));
                var prev: ?*FreeList.Node = null;

                while (current.next) |next| {
                    prev = current;
                    current = next;
                }

                const ret_ptr = current.inner;

                if (current == &self.list[len - 1].?) {
                    // The current node is also the head, meaning that there's only one
                    // element in this linked list. Nodes in self.list are deallocated by another
                    // part of the program, so we just want to set the ?FreeList.Node to null
                    self.list[len - 1] = null;
                } else {
                    std.debug.assert(prev != null); // this is invaraibly true if current != the head node
                    std.debug.assert(prev.?.next == current); // FIXME: is this ptr comparison even valuable?

                    prev.?.next = null; // remove node from linked list
                    allocator.destroy(current);
                }

                // this is safe because we've grabbed this many-ptr from the linked list of AMTs that have this size
                return ret_ptr[0..len];
            }

            pub fn create(self: *FreeList, allocator: Allocator, comptime T: type) !*T {
                return @ptrCast(try self.alloc(allocator, T, 1));
            }

            /// Free'd nodes aren't deallocated, but instead are tracked by a free list where they
            /// may be reused in the future
            ///
            /// We may allocate to append a new FreeList Node to the end of the Linked List
            pub fn free(self: *FreeList, allocator: Allocator, ptr: []Self.Node) !void {
                if (ptr.len == 0 or ptr.len > table_size) return error.unexpected_table_length;

                var current: *FreeList.Node = &(self.list[ptr.len - 1] orelse {
                    // There were no nodes present so start off the linked list
                    self.list[ptr.len - 1] = .{ .inner = ptr.ptr };
                    return;
                });

                // traverse the linked list
                while (current.next) |next| current = next;

                const tail = try allocator.create(FreeList.Node);
                tail.* = .{ .inner = ptr.ptr };

                current.next = tail;
            }

            pub fn destroy(self: *FreeList, allocator: Allocator, node: *Self.Node) !void {
                self.free(allocator, @as([*]Self.Node, @ptrCast(node))[0..1]);
            }
        };

        pub fn init(allocator: Allocator) !Self {
            // TODO: Add ability to have a larger root node (for quicker lookup times)
            const root = try allocator.alloc(?*Node, table_size);
            std.mem.set(?*Node, root, null);

            return Self{ .root = root, .free_list = try FreeList.init(allocator) };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            for (self.root) |maybe_node| {
                const node = maybe_node orelse continue;

                _deinit(allocator, node);
                allocator.destroy(node);
            }

            allocator.free(self.root);
            self.free_list.deinit(allocator);
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
            const shift_amt: Log2Int(Digest) = @intCast(table_size - offset);

            return @truncate(hash >> shift_amt);
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
                const node = try self.free_list.create(allocator, Node);
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
                            const new_base = try self.free_list.alloc(allocator, Node, old_len + 1);
                            const new_map = table.map | mask;

                            var i: Log2Int(Digest) = 0;
                            for (0..table_size) |shift| {
                                const mask_loop = @as(Digest, 1) << @as(Log2Int(Digest), @intCast(shift));

                                if (new_map & mask_loop != 0) {
                                    defer i += 1;

                                    const idx = @popCount(table.map & (mask_loop - 1));
                                    const copy = if (mask == mask_loop) Node{ .kv = Pair{ .key = key, .value = value } } else table.base[idx];
                                    new_base[i] = copy;
                                }
                            }

                            try self.free_list.free(allocator, table.base[0..old_len]);
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
                                const pairs = try self.free_list.alloc(allocator, Node, 2);
                                const map = mask | prev_mask;

                                pairs[@popCount(map & (prev_mask - 1))] = .{ .kv = prev_pair };
                                pairs[@popCount(map & (mask - 1))] = .{ .kv = .{ .key = key, .value = value } };

                                current.* = .{ .table = .{ .map = map, .base = pairs.ptr } };
                                return;
                            },
                            .eq => {
                                const copied_pair = try self.free_list.create(allocator, Node);
                                copied_pair.* = .{ .kv = prev_pair };

                                current.* = .{ .table = .{ .map = mask, .base = @as([*]Node, @ptrCast(copied_pair)) } };
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
    const allocator = std.testing.allocator;
    var trie = try StringTrie.init(allocator);
    defer trie.deinit(allocator);
}

test "init and deinit" {
    const allocator = std.testing.allocator;

    var trie = try StringTrie.init(allocator);
    defer trie.deinit(allocator);
}

test "trie insert" {
    const allocator = std.testing.allocator;

    var trie = try StringTrie.init(allocator);
    defer trie.deinit(allocator);

    try trie.insert(allocator, "hello", {});
    try trie.insert(allocator, "world", {});
}

test "trie search" {
    const Pair = StringTrie.Pair;
    const allocator = std.testing.allocator;

    var trie = try StringTrie.init(allocator);
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

    var trie = try StringTrie.init(allocator);
    defer trie.deinit(allocator);

    try trie.insert(allocator, "hello", {});

    try std.testing.expectEqual(@as(?Pair, .{ .key = "hello", .value = {} }), trie.search("hello"));
    try std.testing.expectEqual(@as(?Pair, null), trie.search("world"));
}
