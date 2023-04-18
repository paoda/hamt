comptime {
    _ = @import("lib.zig");
    _ = @import("trie.zig");
}

test {
    @import("std").testing.refAllDecls(@This());
}
