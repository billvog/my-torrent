//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 29/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();
const stderr = std.io.getStdErr().writer();

const commands = @import("commands.zig").Commands;

const min_arguments = 4;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < min_arguments) {
        try printUsage(args[0]);
    }

    const command = args[1];
    const file_path = try getFilePath(args);

    // Print the information of the torrent file.
    if (std.mem.eql(u8, command, "info")) {
        try commands.printTorrentInfo(allocator, file_path);
    }
    // Print the peers of the torrent.
    else if (std.mem.eql(u8, command, "peers")) {
        try commands.printTorrentPeers(allocator, file_path);
    }
    // Perform a handshake with the torrent.
    else if (std.mem.eql(u8, command, "handshake")) {
        try commands.performTorrentHandshake(allocator, file_path);
    }
    // Invalid command. Print usage and exit.
    else {
        try printUsage(args[0]);
    }
}

fn printUsage(exe: []const u8) !void {
    try stdout.print(
        \\ my-torrent - A BitTorrent client written in Zig.
        \\
        \\ Usage: {s} <command> [options]
        \\
        \\ Commands:
        \\
        \\   info         Print the information of the torrent.
        \\                This doesn't make any network requests. It just reads and decodes the torrent file.
        \\
        \\   peers        Print the peers of the torrent.
        \\                This fetches the peers from the tracker, prints them and exits.
        \\
        \\   handshake    Perform a handshake with one peer.
        \\                This fetches the peers from the tracker, tries to perform a handshake with one of them and exits.
        \\
        \\ Options: 
        \\
        \\   -f <file>    The path to the torrent file.
        \\
    , .{exe});
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
