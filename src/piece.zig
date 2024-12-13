//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 12/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");

const Torrent = @import("torrent.zig").Torrent;
const peer = @import("peer.zig");
const queue = @import("thread_queue.zig");

pub const PeerQueue = queue.Queue(*const peer.Peer);

const QueuedPiece = struct {
    index: u32,
};

pub const DownloadQueue = queue.Queue(QueuedPiece);

pub const DownloadedPiece = struct {
    index: u32,
    data: []u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

pub const DownloadWorkerContext = struct {
    piece_queue: *DownloadQueue,
    peer_queue: *PeerQueue,
    torrent: *Torrent,
    result_buffer: *std.ArrayList(DownloadedPiece),
    result_mutex: *std.Thread.Mutex,
    is_connected: std.atomic.Value(bool),
};

const ConnectedPeer = struct {
    peer: *const peer.Peer,
    stream: peer.Stream,
    failed_attempts: u16,
};

/// Connect to a peer from the queue.
fn connectToPeer(peer_queue: *PeerQueue) !ConnectedPeer {
    while (true) {
        const item = peer_queue.pop() orelse return error.NoPeers;

        const stream = item.connect() catch |err| {
            std.log.warn("Failed to connect to peer: {}", .{err});

            // Re-queue peer
            peer_queue.push(item) catch {
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
}

// Thread function to download pieces.
pub fn downloadWorkerThread(context: *DownloadWorkerContext) void {
    var connected: ?ConnectedPeer = null;
    var last_keepalive = std.time.milliTimestamp();

    while (true) {
        if (connected == null) {
            context.is_connected.store(false, .release);
            connected = connectToPeer(context.peer_queue) catch |err| {
                std.log.warn("No more peers available: {}", .{err});
                break;
            };
        }

        context.is_connected.store(true, .release);

        // Send keepalive every 2 minutes
        if (std.time.milliTimestamp() - last_keepalive >= 2 * std.time.ms_per_s) {
            connected.?.peer.keepAlive(&connected.?.stream) catch |err| {
                std.log.warn("Error sending keepalive: {}", .{err});
            };

            last_keepalive = std.time.milliTimestamp();
        }

        // Get next piece from queue
        const piece_info = context.piece_queue.pop() orelse break;

        // Download the piece
        const piece_data = connected.?.peer.downloadPiece(&connected.?.stream, piece_info.index) catch |err| {
            if (err == error.BrokenPipe) {
                std.log.warn("Peer disconnected", .{});
                break;
            }

            std.log.warn("Error downloading piece: {}: {}", .{ piece_info.index, err });

            // Re-queue piece
            context.piece_queue.push(.{ .index = piece_info.index }) catch {
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

        context.result_mutex.lock();
        defer context.result_mutex.unlock();

        // Store the result
        context.result_buffer.append(.{
            .index = piece_info.index,
            .data = piece_data,
        }) catch continue;
    }
}

const FileSpan = struct {
    file_index: usize,
    piece_offset: u32,
    file_offset: u32,
    length: u32,
};

pub fn getPieceFileSpans(allocator: std.mem.Allocator, torrent: *const Torrent, piece_index: u32) ![]FileSpan {
    var spans = std.ArrayList(FileSpan).init(allocator);

    const piece_size = torrent.metadata.info.piece_length;
    const piece_offset = @as(u32, piece_index * piece_size);

    var current_offset: u32 = 0;
    var remaining = piece_size;

    // Iterate through files to find which ones this piece intersects
    for (torrent.metadata.info.files.items, 0..) |file, i| {
        if (current_offset + file.length <= piece_offset) {
            // This file ends before our piece starts
            current_offset += file.length;
            continue;
        }

        if (current_offset >= piece_offset + piece_size) {
            // This file starts after our piece ends
            break;
        }

        // Calculate overlap
        const file_start = if (current_offset < piece_offset)
            piece_offset - current_offset
        else
            0;

        const available = @as(u32, file.length - file_start);
        const span_length = @as(u32, @min(remaining, available));

        try spans.append(.{
            .file_index = i,
            .piece_offset = if (current_offset >= piece_offset)
                current_offset - piece_offset
            else
                0,
            .file_offset = file_start,
            .length = span_length,
        });

        remaining -= span_length;
        if (remaining == 0) break;

        current_offset += file.length;
    }

    return spans.toOwnedSlice();
}
