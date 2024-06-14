const std = @import("std");

pub fn scanDir(allocator: std.mem.Allocator, startPath: []const u8) !std.ArrayList([]const u8) {
    var startDir = try std.fs.openDirAbsolute(startPath, std.fs.Dir.OpenDirOptions{
        .access_sub_paths = true,
        .iterate = true,
    });
    defer startDir.close();

    var fileList: std.ArrayList([]const u8) = std.ArrayList([]const u8).init(allocator);

    var walker = try startDir.walk(allocator);

    while (try walker.next()) |entry| {
        if (entry.kind == std.fs.Dir.Entry.Kind.file) {
            const paths = [_][]const u8{startPath, entry.basename};
            const fullPath = try std.fs.path.join(allocator, &paths);

            try fileList.append(fullPath);
        }
    }

    return fileList;
}
