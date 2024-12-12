//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 12/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");

const Torrent = @import("torrent.zig").Torrent;
const peer = @import("peer.zig");

const MAX_PIECE_RETRIES = 3;

const QueuedPiece = struct {
    index: u32,
    retries: u32,
};

pub const DownloadQueue = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    pieces: std.ArrayList(QueuedPiece),

    pub fn init(allocator: std.mem.Allocator) DownloadQueue {
        return .{
            .mutex = .{},
            .pieces = std.ArrayList(QueuedPiece).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DownloadQueue) void {
        self.pieces.deinit();
    }

    pub fn push(self: *DownloadQueue, piece: QueuedPiece) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.pieces.append(piece);
    }

    pub fn pop(self: *DownloadQueue) ?QueuedPiece {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.pieces.items.len == 0) return null;
        return self.pieces.orderedRemove(0);
    }
};

pub const DownloadedPiece = struct {
    index: u32,
    data: []u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

pub const DownloadWorkerContext = struct {
    queue: *DownloadQueue,
    peer: *peer.Peer,
    torrent: *Torrent,
    result_buffer: *std.ArrayList(DownloadedPiece),
    result_mutex: *std.Thread.Mutex,
};

// Thread function to download pieces.
pub fn downloadWorkerThread(context: *DownloadWorkerContext) void {
    // Open stream
    var stream = context.peer.connect() catch |err| {
        std.debug.print("Failed to init peer: {}\n", .{err});
        return;
    };
    defer stream.close();

    while (true) {
        // Get next piece from queue
        const piece_info = context.queue.pop() orelse break;

        // Download the piece
        const piece_data = context.peer.downloadPiece(&stream, piece_info.index) catch |err| {
            std.debug.print("Error downloading piece: {}: {}\n", .{ piece_info.index, err });

            // Re-queue if under max retries
            if (piece_info.retries < MAX_PIECE_RETRIES) {
                context.queue.push(.{
                    .index = piece_info.index,
                    .retries = piece_info.retries + 1,
                }) catch {
                    std.debug.print("Failed to re-queue piece {}\n", .{piece_info.index});
                };
            } else {
                std.debug.print("Piece {} failed after {} retries\n", .{ piece_info.index, MAX_PIECE_RETRIES });
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
