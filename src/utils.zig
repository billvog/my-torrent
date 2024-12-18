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

pub fn splitHostPort(url: []const u8) !struct { proto: []const u8, host: []const u8, port: ?u16 } {
    // Find protocol separator
    const proto_end = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const host_start = proto_end + 3;
    const path_start = std.mem.indexOf(u8, url[host_start..], "/");

    // Find port separator
    const port_sep = std.mem.lastIndexOf(u8, url[host_start..], ":") orelse 0;
    const has_port = port_sep > 0; // If port_sep is 0, there is no port.
    const port_start = if (has_port) host_start + port_sep + 1 else 0;
    const port_end = if (path_start) |ps| host_start + ps else url.len;

    // Find host end
    var host_end: usize = 0;
    if (has_port) {
        host_end = host_start + port_sep;
    } else if (path_start) |ps| {
        host_end = host_start + ps;
    } else {
        host_end = url.len;
    }

    // Extract proto(col), hostname and port (if any)
    const proto = url[0..proto_end];
    const hostname = url[host_start..host_end];
    const port: ?u16 = if (has_port) try std.fmt.parseInt(u16, url[port_start..port_end], 10) else null;

    return .{
        .proto = proto,
        .host = hostname,
        .port = port,
    };
}
