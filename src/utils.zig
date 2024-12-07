//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 30/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const crypto = std.crypto;

pub fn readFileIntoString(allocator: std.mem.Allocator, file_path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const file_size = try file.getEndPos();

    const buffer = try allocator.alloc(u8, file_size);
    errdefer allocator.free(buffer);

    _ = file.readAll(buffer) catch {
        return error.CannotReadFile;
    };

    return buffer;
}

pub fn generateRandomString(allocator: std.mem.Allocator, size: usize) ![]const u8 {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    const result = try allocator.alloc(u8, size);
    errdefer allocator.free(result);

    for (result) |*char| {
        const random_index = crypto.random.intRangeAtMost(u8, 0, charset.len - 1);
        char.* = charset[random_index];
    }

    return result;
}
