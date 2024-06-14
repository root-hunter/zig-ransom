const std = @import("std");
const aes = std.crypto.aead.aes_gcm.Aes256Gcm;

const EngineError = error{NotValidFilePointer};

//const CHUNK_SIZE: usize = std.mem.page_size;
const CHUNK_SIZE: usize = 128;

pub const Chunk = struct {
    data: []u8,
    tag: []u8,

    pub fn init(allocator: std.mem.Allocator, data: []u8, tag: [aes.tag_length]u8) !Chunk {
        const tmpData = try allocator.alloc(u8, data.len);
        const tmpTag = try allocator.alloc(u8, aes.tag_length);

        std.mem.copyBackwards(u8, tmpData, data);
        std.mem.copyBackwards(u8, tmpTag, &tag);

        return Chunk{ .data = tmpData, .tag = tmpTag };
    }

    pub fn pack(self: Chunk, allocator: std.mem.Allocator) ![]const u8 {
        const size = aes.tag_length + self.data.len;
        std.log.debug("LEN: {}", .{self.data.len});

        var tmp = try allocator.alloc(u8, size);

        var k: usize = 0;

        var i: usize = 0;
        while (i < self.tag.len) {
            tmp[k] = self.tag[i];

            k += 1;
            i += 1;
        }

        i = 0;
        while (i < self.data.len) {
            tmp[k] = self.data[i];

            k += 1;
            i += 1;
        }

        return tmp;
    }

    pub fn encrypt(self: Chunk) !void {
        _ = self;
    }

    pub fn decrypt(self: Chunk) !void {
        _ = self;
    }
};

pub const File = struct {
    file: std.fs.File,
    fileSize: usize = 0,
    filePath: []const u8,
    metadata: std.fs.File.Metadata,

    chunks: *std.ArrayList(Chunk),

    pub fn init(allocator: std.mem.Allocator, filePath: []const u8) !File {
        var file = try std.fs.openFileAbsolute(filePath, std.fs.File.OpenFlags{ .mode = std.fs.File.OpenMode.read_write });
        errdefer file.close();

        const chunks = try allocator.create(std.ArrayList(Chunk));

        chunks.* = std.ArrayList(Chunk).init(allocator);

        return File{ .file = file, .filePath = filePath, .chunks = chunks, .metadata = try file.metadata() };
    }

    pub fn deinit(self: File) !void {
        self.chunks.deinit();
        self.file.close();
    }

    pub fn encrypt(self: File, allocator: std.mem.Allocator, digest: [aes.key_length]u8) !void {
        const content = try self.file.readToEndAlloc(allocator, 1024 * 1024 * 512);
        const chunkCount: usize = (content.len + (CHUNK_SIZE - 1)) / CHUNK_SIZE;

        std.log.debug("FILE SIZE: {}\nCHUNK COUNT: {}", .{ content.len, chunkCount });

        var j: usize = 0;
        while (j < chunkCount) {
            const startSlice = (j * (CHUNK_SIZE));
            const endSlice = if ((j + 1) * CHUNK_SIZE <= content.len)
                ((j + 1) * CHUNK_SIZE)
            else
                content.len;

            const slice = content[startSlice..endSlice];

            var tag = [_]u8{0} ** aes.tag_length;
            const npub = [_]u8{0} ** aes.nonce_length;
            const ad = [_]u8{};

            const cipherText = try allocator.alloc(u8, slice.len);

            aes.encrypt(cipherText, &tag, slice, &ad, npub, digest);

            const chunk = try Chunk.init(allocator, cipherText, tag);

            if (j < 1000) {
                std.log.debug("startSlice: {} endSlice {}", .{ startSlice, endSlice });
                std.log.debug("startTag: {} endTag {}", .{ endSlice, endSlice + aes.tag_length });

                std.log.debug("{} ENCRYPT ({s})", .{ j, chunk.tag });
                std.log.debug("c: {}, m: {}", .{ chunk.data.len, slice.len });
            }

            //_ = try self.file.write(chunk.data);
            //_ = try self.file.write(&chunk.tag);

            try self.chunks.*.append(chunk);

            j += 1;
        }

        const writer = self.file.writer();

        try self.file.seekTo(0);

        var i: usize = 0;
        while (i < self.chunks.*.items.len) {
            const chunk = self.chunks.*.items[i];
            const pack = try chunk.pack(allocator);

            _ = try writer.write(pack);

            std.log.debug("({}): {any}", .{pack.len, pack});

            i += 1;
        }
    }

    pub fn decrypt(self: File) !void {
        _ = self;
    }

    pub fn getSize(self: File) !u64 {
        return self.metadata.size();
    }
};

pub fn encryptFile(allocator: std.mem.Allocator, filePath: []const u8, digest: *[aes.key_length]u8) !void {
    const file = try std.fs.openFileAbsolute(filePath, std.fs.File.OpenFlags{
        .mode = std.fs.File.OpenMode.read_write,
        .lock = std.fs.File.Lock.exclusive,
    });
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024 * 512);
    const chunkCount: usize = (content.len + (CHUNK_SIZE - 1)) / CHUNK_SIZE;
    try file.seekTo(0);

    std.log.debug("FILE SIZE: {}\nCHUNK COUNT: {}", .{ content.len, chunkCount });

    var j: usize = 0;
    while (j < chunkCount) {
        const startSlice = (j * (CHUNK_SIZE));
        const endSlice = if ((j + 1) * CHUNK_SIZE <= content.len)
            ((j + 1) * CHUNK_SIZE)
        else
            content.len;

        const slice = content[startSlice..endSlice];

        const cipherText = try allocator.alloc(u8, slice.len);
        defer allocator.free(cipherText);

        var tag = [_]u8{0} ** aes.tag_length;
        const npub = [_]u8{0} ** aes.nonce_length;
        const ad = [_]u8{};

        aes.encrypt(cipherText, &tag, slice, &ad, npub, digest.*);

        if (j < 10) {
            std.log.debug("startSlice: {} endSlice {}", .{ startSlice, endSlice });
            std.log.debug("startTag: {} endTag {}", .{ endSlice, endSlice + aes.tag_length });

            std.log.debug("{} ENCRYPT ({s})", .{ j, tag });
        }

        _ = try file.write(cipherText);
        _ = try file.write(&tag);

        j += 1;
    }
}

pub fn decryptFile(allocator: std.mem.Allocator, filePath: []const u8, digest: *[aes.key_length]u8) !void {
    const file = try std.fs.openFileAbsolute(filePath, std.fs.File.OpenFlags{
        .mode = std.fs.File.OpenMode.read_write,
        .lock = std.fs.File.Lock.exclusive,
    });
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024 * 512);
    const size = (CHUNK_SIZE + aes.tag_length);

    const chunkCount: usize = (content.len + (size - 1)) / size;
    try file.seekTo(0);

    std.log.debug("FILE SIZE: {}\nCHUNK COUNT: {}", .{ content.len, chunkCount });

    var j: usize = 0;
    while (j < chunkCount) {
        const startSlice = j * size;
        const endSlice = if (startSlice + CHUNK_SIZE <= content.len)
            startSlice + CHUNK_SIZE
        else
            content.len;

        const slice = content[startSlice..endSlice];
        const tagSlice = content[endSlice..(endSlice + aes.tag_length)];

        std.log.debug("##################################", .{});
        std.log.debug("startSlice: {} endSlice {}", .{ startSlice, endSlice });
        std.log.debug("startTag: {} endTag {}", .{ endSlice, (endSlice + aes.tag_length) });

        var tag: [aes.tag_length]u8 = [_]u8{0} ** aes.tag_length;
        @memcpy(&tag, tagSlice);

        const message = try allocator.alloc(u8, slice.len);
        defer allocator.free(message);

        const npub = [_]u8{0} ** aes.nonce_length;
        const ad = [_]u8{};

        std.log.debug("{} DECRYPT ({s})", .{ j, tag });

        try aes.decrypt(message, slice, tag, &ad, npub, digest.*);

        _ = try file.write(message);

        j += 1;
    }
}
