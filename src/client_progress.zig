//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 14/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();

pub const ClientProgress = struct {
    allocator: std.mem.Allocator,

    thread: std.Thread,

    started_time: i64,
    downloaded_pieces: *std.atomic.Value(usize),
    total_pieces: *usize,
    connected_peers: *std.atomic.Value(usize),
    should_stop: *std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        downloaded_pieces: *std.atomic.Value(usize),
        total_pieces: *usize,
        connected_peers: *std.atomic.Value(usize),
        should_stop: *std.atomic.Value(bool),
    ) !*ClientProgress {
        const self = try allocator.create(ClientProgress);
        errdefer allocator.destroy(self);

        self.* = ClientProgress{
            .allocator = allocator,
            .thread = try std.Thread.spawn(.{}, ClientProgress.updateLoop, .{self}),
            .started_time = std.time.milliTimestamp(),
            .downloaded_pieces = downloaded_pieces,
            .total_pieces = total_pieces,
            .connected_peers = connected_peers,
            .should_stop = should_stop,
        };

        return self;
    }

    pub fn deinit(self: *@This()) void {
        self.thread.join();
        self.allocator.destroy(self);
    }

    pub fn updateLoop(self: *@This()) void {
        // If default log is enabled, abandon thread.
        if (std.log.defaultLogEnabled(.info)) {
            return;
        }

        while (!self.should_stop.load(.monotonic)) {
            // Update once per quarter second.
            defer std.time.sleep(250 * std.time.ns_per_ms);

            const downloaded_pieces = self.downloaded_pieces.load(.monotonic);
            const connected_peers = self.connected_peers.load(.monotonic);
            const percentage = @as(f64, @floatFromInt(downloaded_pieces)) * 100.0 / @as(f64, @floatFromInt(self.total_pieces.*));

            stdout.print("\rDownloaded {d:.2}% ({d}/{d} pieces) | Connected to {d} peers | {d}s passed\t", .{
                percentage,
                downloaded_pieces,
                self.total_pieces.*,
                connected_peers,
                @divTrunc((std.time.milliTimestamp() - self.started_time), 1000),
            }) catch |err| {
                std.log.err("Error printing progress: {}", .{err});
            };
        }
    }
};
