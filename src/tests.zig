comptime {
    _ = @import("HashArrayMappedTrie.zig");
    _ = @import("main.zig");
}

test {
    @import("std").testing.refAllDecls(@This());
}
