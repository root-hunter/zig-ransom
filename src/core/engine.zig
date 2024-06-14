const std = @import("std");
const aes = std.crypto.aead.aes_gcm.Aes256Gcm;

//const CHUNK_SIZE: usize = std.mem.page_size;
const CHUNK_SIZE: usize = 128;

const Chunk = struct {
    data: [CHUNK_SIZE] u8 = [_]u8{0} ** CHUNK_SIZE,
    tag: [aes.tag_length] u8 = [_]u8{0} ** aes.tag_length,
    file: File = undefined,

    pub fn init(self: Chunk, file: File) !void {
        self.file = file;
    }

    pub fn encrypt(self: Chunk) !void {
        _ = self;
    }

    pub fn decrypt(self: Chunk) !void {
        _ = self;
    }
};

const File = struct {
    fd: std.fs.File,
    fileSize: usize,
    filePath: [] const u8,
    metadata: std.fs.File.Metadata = undefined,

    chunks: std.ArrayList(Chunk) = undefined,
    allocator: std.mem.Allocator = undefined,

    pub fn init(self: File, allocator: std.mem.Allocator, filePath: [] const u8) !void {
        self.allocator = allocator;
        self.filePath = filePath;
        self.chunks = std.ArrayList(Chunk).init(self.allocator);

        self.fd = std.fs.openFileAbsolute(self.filePath, std.fs.File.OpenFlags{
            .mode = std.fs.File.OpenMode.read_write
        });

        self.metadata = try self.fd.metadata();
    }

    pub fn deinit(self: File) void {
        if(self.chunks != undefined) {
            self.chunks.deinit();
        }
        
        if(self.fd != undefined) {
            self.fd.close();
        }
    }

    pub fn encrypt(self: File) !void {
        _ = self;
    }

    pub fn decrypt(self: File) !void {
        _ = self;
    }

    pub fn getSize(self: File) !u64 {
        return self.metadata.size();
    }
};

pub fn encryptFile(allocator: std.mem.Allocator, filePath: []const u8, digest: *[aes.key_length]u8) !void {
    const file = try std.fs.openFileAbsolute(
        filePath,
        std.fs.File.OpenFlags{ 
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

        if(j < 10) {
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
    const file = try std.fs.openFileAbsolute(
        filePath,
        std.fs.File.OpenFlags{ 
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
        
        std.log.debug("##################################", .{ });
        std.log.debug("startSlice: {} endSlice {}", .{ startSlice, endSlice });
        std.log.debug("startTag: {} endTag {}", .{ endSlice, (endSlice + aes.tag_length) });

        var tag: [aes.tag_length] u8 = [_]u8{0} ** aes.tag_length;
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
