//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 30/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

const torrent = @import("torrent.zig");

pub const Commands = struct {
    /// Print the information of the torrent file.
    pub fn printTorrentInfo(allocator: std.mem.Allocator, file_path: []const u8) !void {
        const my_torrent = try openTorrentFile(allocator, file_path);
        defer my_torrent.deinit();

        const metadata = my_torrent.metadata;

        try stdout.print("Tracker URL: {s}\n", .{metadata.announce});
        if (metadata.created_by) |created_by| try stdout.print("Created By: {s}\n", .{created_by});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(metadata.info_hash, .lower)});
        try stdout.print("Info:\n", .{});
        try stdout.print("  Name: {s}\n", .{metadata.info.name});
        try stdout.print("  Length: {}\n", .{std.fmt.fmtIntSizeDec(metadata.info.length)});
        try stdout.print("  Piece Length: {d}\n", .{std.fmt.fmtIntSizeDec(metadata.info.piece_length)});
        try stdout.print("  Pieces:\n", .{});
        for (metadata.info.pieces.items) |piece| {
            try stdout.print("    {s}\n", .{std.fmt.bytesToHex(piece[0..20], .lower)});
        }
    }

    /// Download the torrent.
    pub fn printTorrentPeers(allocator: std.mem.Allocator, file_path: []const u8) !void {
        const my_torrent = try openTorrentFile(allocator, file_path);
        defer my_torrent.deinit();

        try stdout.print("Tracker URL: {s}\n", .{my_torrent.metadata.announce});
        try my_torrent.getPeers();
    }

    /// Opens torrent file and displays an error message if it fails.
    fn openTorrentFile(allocator: std.mem.Allocator, file_path: []const u8) !torrent.Torrent {
        return torrent.Torrent.init(allocator, file_path) catch |err| {
            switch (err) {
                error.InvalidTorrentFile => {
                    try stderr.print("Error: Invalid torrent file\n", .{});
                },
                error.FileNotFound, error.CannotReadFile => {
                    try stderr.print("Error: Cannot open file\n", .{});
                },
                else => {
                    try stderr.print("Error: Unknown error\n", .{});
                },
            }

            std.process.exit(1);
        };
    }
};
