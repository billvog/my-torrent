//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 29/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const torrent = @import("torrent.zig");

const allocator = std.heap.page_allocator;
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

const min_arguments = 4;

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < min_arguments) {
        try printUsage(args[0]);
    }

    const command = args[1];

    // Print the information of the torrent file.
    if (std.mem.eql(u8, command, "info")) {
        const file_path = try getFilePath(args);

        const my_torrent = torrent.Torrent.init(allocator, file_path) catch |err| {
            switch (err) {
                error.CannotReadFile => {
                    try stderr.print("Error: Cannot read file\n", .{});
                },
                error.InvalidTorrentFile, error.MissingAnnounceKey, error.MissingInfoKey, error.MissingLengthKey => {
                    try stderr.print("Error: Invalid torrent file\n", .{});
                },
                else => {
                    try stderr.print("Error: Unknown error\n", .{});
                },
            }
            std.process.exit(1);
        };

        try stdout.print("Tracker URL: {s}\n", .{my_torrent.metadata.announce});
        if (my_torrent.metadata.created_by) |created_by| {
            try stdout.print("Created By: {s}\n", .{created_by});
        }
        try stdout.print("Info:\n", .{});
        try stdout.print("  Name: {s}\n", .{my_torrent.metadata.info.name});
        try stdout.print("  Length: {}\n", .{std.fmt.fmtIntSizeDec(my_torrent.metadata.info.length)});
        try stdout.print("  Piece Length: {d}\n", .{std.fmt.fmtIntSizeDec(my_torrent.metadata.info.piece_length)});
    }
}

fn printUsage(exe: []const u8) !void {
    try stdout.print("Usage: {s} info -f <torrent>\n", .{exe});
    std.process.exit(1);
}

fn getFilePath(args: [][]const u8) ![]const u8 {
    if (args.len < min_arguments) {
        try printUsage(args[0]);
    }

    if (std.mem.eql(u8, args[2], "-f") == false) {
        try printUsage(args[0]);
    }

    const path = args[3];
    return path;
}
