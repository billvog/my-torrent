//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 29/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();
const allocator = std.heap.page_allocator;
const bencode = @import("bencode.zig");

const MinArgs = 4;

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < MinArgs) {
        try printUsage(args[0]);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        const encodedStr = try getEncodedStr(args);
        defer allocator.free(encodedStr);

        const decoded = bencode.decode(allocator, encodedStr) catch |err| {
            try stderr.print("Error: {s}\n", .{bencode.errorToString(err)});
            std.process.exit(1);
        };

        defer bencode.cleanupToken(allocator, &decoded);

        const trackerUrl = decoded.Dictionary.get("announce") orelse {
            try stdout.print("Error: No announce key found in dictionary\n", .{});
            std.process.exit(1);
        };

        const info = decoded.Dictionary.get("info") orelse {
            try stdout.print("Error: No info key found in dictionary\n", .{});
            std.process.exit(1);
        };

        const length = info.Dictionary.get("length") orelse {
            try stdout.print("Error: No length key found in dictionary\n", .{});
            std.process.exit(1);
        };

        try stdout.print("Tracker URL: {s}\n", .{trackerUrl.String});
        try stdout.print("Length: {d}\n", .{length.Integer});
    }
}

fn printUsage(exe: []const u8) !void {
    try stdout.print("Usage: {s} decode -f <torrent>\n", .{exe});
    std.process.exit(1);
}

fn getEncodedStr(args: [][]const u8) ![]const u8 {
    if (args.len < MinArgs) {
        try printUsage(args[0]);
    }

    if (std.mem.eql(u8, args[2], "-f") == false) {
        try printUsage(args[0]);
    }

    const path = args[3];

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const fileSize = try file.getEndPos();

    const buffer = try allocator.alloc(u8, fileSize);
    _ = file.readAll(buffer) catch {
        try stderr.print("Error: Unable to read file: {s}\n", .{path});
        std.process.exit(1);
    };

    return buffer;
}
