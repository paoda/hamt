comptime {
    _ = @import("trie.zig");
}

test {
    @import("std").testing.refAllDecls(@This());
}
