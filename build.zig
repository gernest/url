const Builder = @import("std").build.Builder;
const mod = @import("mod.zig");

pub fn build(b: *Builder) void {
    mod.build(b);
}
