//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 15/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");

const peer = @import("peer.zig");
const Queue = @import("thread_queue.zig").Queue;
const Torrent = @import("torrent.zig").Torrent;

pub const PeerQueue = Queue(*const peer.Peer);

pub const QueuedPiece = struct {
    index: u32,
};

pub const DownloadQueue = Queue(QueuedPiece);

pub const DownloadedPiece = struct {
    index: u32,
    data: []u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

const ConnectedPeer = struct {
    peer: *const peer.Peer,
    stream: peer.Stream,
    failed_attempts: u16,
};

pub const Downloader = struct {
    allocator: std.mem.Allocator,

    thread: std.Thread,
    mutex: *std.Thread.Mutex,

    is_connected: std.atomic.Value(bool),

    peer_queue: *PeerQueue,
    piece_queue: *DownloadQueue,
    should_stop: *std.atomic.Value(bool),
    result_buffer: *std.ArrayList(DownloadedPiece),

    torrent: *Torrent,

    pub fn init(
        allocator: std.mem.Allocator,
        mutex: *std.Thread.Mutex,
        peer_queue: *PeerQueue,
        piece_queue: *DownloadQueue,
        result_buffer: *std.ArrayList(DownloadedPiece),
        should_stop: *std.atomic.Value(bool),
        torrent: *Torrent,
    ) !*Downloader {
        const self = try allocator.create(Downloader);
        errdefer allocator.destroy(self);

        self.* = Downloader{
            .allocator = allocator,
            .is_connected = std.atomic.Value(bool).init(false),
            .mutex = mutex,
            .peer_queue = peer_queue,
            .piece_queue = piece_queue,
            .result_buffer = result_buffer,
            .should_stop = should_stop,
            .thread = try std.Thread.spawn(.{}, Downloader.updateLoop, .{self}),
            .torrent = torrent,
        };

        return self;
    }

    pub fn deinit(self: *@This()) void {
        self.thread.join();
        self.allocator.destroy(self);
    }

    pub fn updateLoop(self: *@This()) void {
        var connected: ?ConnectedPeer = null;
        var last_keepalive = std.time.milliTimestamp();

        while (!self.should_stop.load(.monotonic)) {
            // Connect to peer if not already connected
            if (connected == null) {
                self.is_connected.store(false, .release);
                connected = self.connectToPeer() catch |err| {
                    if (err != error.ShouldStop) {
                        std.log.warn("No more peers available: {}", .{err});
                    }

                    break;
                };
            }

            self.is_connected.store(true, .release);

            // Check if we should stop before downloading a piece
            if (self.should_stop.load(.monotonic)) {
                break;
            }

            // Send keepalive every 2 minutes
            if (std.time.milliTimestamp() - last_keepalive >= 2 * std.time.ms_per_s) {
                connected.?.peer.keepAlive(&connected.?.stream) catch |err| {
                    std.log.warn("Error sending keepalive: {}", .{err});
                };

                last_keepalive = std.time.milliTimestamp();
            }

            // Get next piece from queue...
            const piece_info = self.piece_queue.pop() orelse break;

            // ...and download it
            const piece_data = connected.?.peer.downloadPiece(&connected.?.stream, piece_info.index) catch |err| {
                if (err == error.BrokenPipe) {
                    std.log.warn("Peer disconnected", .{});
                    break;
                }

                std.log.warn("Error downloading piece: {}: {}", .{ piece_info.index, err });

                // Re-queue piece
                self.piece_queue.push(.{ .index = piece_info.index }) catch {
                    std.log.warn("Failed to re-queue piece {}", .{piece_info.index});
                };

                // If we have too many failed attempts, disconnect peer
                connected.?.failed_attempts += 1;
                if (connected.?.failed_attempts >= 3) {
                    std.log.warn("Too many failed attempts, disconnecting peer", .{});
                    connected.?.stream.close();
                    connected = null;
                }

                // Continue to next piece
                continue;
            };

            self.mutex.lock();
            defer self.mutex.unlock();

            // Store the result
            self.result_buffer.append(.{
                .index = piece_info.index,
                .data = piece_data,
            }) catch continue;
        }
    }

    /// Connect to a peer from the queue.
    fn connectToPeer(self: *@This()) !ConnectedPeer {
        while (!self.should_stop.load(.monotonic)) {
            const item = self.peer_queue.pop() orelse return error.NoPeers;

            const stream = item.connect() catch |err| {
                std.log.warn("Failed to connect to peer: {}", .{err});

                // Re-queue peer
                self.peer_queue.push(item) catch {
                    std.log.warn("Failed to re-queue peer", .{});
                };

                continue;
            };

            return .{
                .peer = item,
                .stream = stream,
                .failed_attempts = 0,
            };
        }

        return error.ShouldStop;
    }
};
