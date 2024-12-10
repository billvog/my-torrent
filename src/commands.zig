//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 30/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

const Torrent = @import("torrent.zig").Torrent;
const Client = @import("client.zig").Client;

pub const Commands = struct {
    /// Print the information of the torrent file.
    pub fn printTorrentInfo(allocator: std.mem.Allocator, file_path: []const u8) !void {
        const torrent = try openTorrentFile(allocator, file_path);
        defer torrent.deinit();

        const metadata = torrent.metadata;

        try stdout.print("Tracker URLs:\n", .{});
        for (metadata.announce_urls) |announce| {
            try stdout.print("  {s}\n", .{announce});
        }
        if (metadata.created_by) |created_by| try stdout.print("Created By: {s}\n", .{created_by});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(metadata.info_hash, .lower)});
        try stdout.print("Info:\n", .{});
        try stdout.print("  Files:\n", .{});
        for (metadata.info.files.items) |file| {
            try stdout.print("   - Name: {s}\n", .{file.path});
            try stdout.print("     Length: {}\n", .{std.fmt.fmtIntSizeDec(file.length)});
        }
        try stdout.print("  Total Length: {d}\n", .{std.fmt.fmtIntSizeDec(metadata.info.total_length)});
        try stdout.print("  Piece Length: {d}\n", .{std.fmt.fmtIntSizeDec(metadata.info.piece_length)});
        try stdout.print("  Pieces:\n", .{});
        for (metadata.info.pieces[0..10]) |piece| {
            try stdout.print("    {s}\n", .{std.fmt.bytesToHex(piece[0..20], .lower)});
        }
        if (metadata.info.pieces.len > 10) {
            try stdout.print("    ...\n", .{});
        }
    }

    /// Print the peers of the torrent.
    pub fn printTorrentPeers(allocator: std.mem.Allocator, file_path: []const u8) !void {
        var torrent = try openTorrentFile(allocator, file_path);
        defer torrent.deinit();

        var client = Client.init(allocator, &torrent);

        try stdout.print("Fetching peers from trackers...\n", .{});

        const peers = try client.getPeers();
        defer peers.deinit();

        try stdout.print("Peers:\n", .{});

        for (peers.items) |peer| {
            const peer_str = try peer.toSlice(allocator);
            defer allocator.free(peer_str);

            try stdout.print("  {s}\n", .{peer_str});
        }
    }

    /// Download a piece of the torrent.
    pub fn downloadTorrent(allocator: std.mem.Allocator, file_path: []const u8, output_file: []const u8) !void {
        var torrent = try openTorrentFile(allocator, file_path);
        defer torrent.deinit();

        try stdout.print("Downloading torrent...\n", .{});

        var client = Client.init(allocator, &torrent);
        client.download(output_file) catch |err| {
            try stderr.print("Error: Failed to download: {}\n", .{err});
            std.process.exit(1);
        };
    }

    /// Opens torrent file and displays an error message if it fails.
    fn openTorrentFile(allocator: std.mem.Allocator, file_path: []const u8) !Torrent {
        return Torrent.init(allocator, file_path) catch |err| {
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
