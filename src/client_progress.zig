//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 14/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();

pub const ProgressContext = struct {
    started_time: i64,
    downloaded_pieces: *std.atomic.Value(usize),
    total_pieces: *usize,
    connected_peers: *std.atomic.Value(usize),
    should_stop: *std.atomic.Value(bool),
};

pub fn progressWorkerThread(context: *ProgressContext) void {
    // If default log is enabled, abandon thread.
    if (std.log.defaultLogEnabled(.info)) {
        return;
    }

    while (!context.should_stop.load(.monotonic)) {
        // Update once per quarter second.
        defer std.time.sleep(250 * std.time.ns_per_ms);

        const downloaded_pieces = context.downloaded_pieces.load(.monotonic);
        const connected_peers = context.connected_peers.load(.monotonic);
        const percentage = @as(f64, @floatFromInt(downloaded_pieces)) * 100.0 / @as(f64, @floatFromInt(context.total_pieces.*));

        stdout.print("\rDownloaded {d:.2}% ({d}/{d} pieces) | Connected to {d} peers | {d}s passed\t", .{
            percentage,
            downloaded_pieces,
            context.total_pieces.*,
            connected_peers,
            @divTrunc((std.time.milliTimestamp() - context.started_time), 1000),
        }) catch |err| {
            std.log.err("Error printing progress: {}", .{err});
        };
    }
}

pub const ClientProgress = struct {
    allocator: std.mem.Allocator,
    context: *ProgressContext,
    thread: *std.Thread,

    pub fn init(
        allocator: std.mem.Allocator,
        downloaded_pieces: *std.atomic.Value(usize),
        total_pieces: *usize,
        connected_peers: *std.atomic.Value(usize),
        should_stop: *std.atomic.Value(bool),
    ) !ClientProgress {
        const context = try allocator.create(ProgressContext);
        context.* = .{
            .started_time = std.time.milliTimestamp(),
            .downloaded_pieces = downloaded_pieces,
            .total_pieces = total_pieces,
            .connected_peers = connected_peers,
            .should_stop = should_stop,
        };

        var thread = try std.Thread.spawn(.{}, progressWorkerThread, .{context});

        return ClientProgress{ .allocator = allocator, .context = context, .thread = &thread };
    }

    pub fn deinit(self: @This()) void {
        self.allocator.destroy(self.context);
        self.thread.join();
    }
};
