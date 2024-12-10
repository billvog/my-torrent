const std = @import("std");

const Torrent = @import("torrent.zig").Torrent;
const tracker = @import("tracker.zig");
const peer = @import("peer.zig");
const piece = @import("piece.zig");

const MAX_DOWNLOAD_THREADS = 4;

pub const Client = struct {
    allocator: std.mem.Allocator,
    torrent: *Torrent,

    pub fn init(allocator: std.mem.Allocator, torrent: *Torrent) Client {
        return .{ .allocator = allocator, .torrent = torrent };
    }

    /// Fetches peers from trackers, using multiple threads.
    pub fn getPeers(self: *@This()) !peer.Peers {
        var tracker_queue = tracker.Queue.init(self.allocator);
        defer tracker_queue.deinit();

        // Fill queue with all piece indices
        for (self.torrent.metadata.announce_urls) |url| {
            try tracker_queue.push(.{
                .tracker = tracker.Tracker{
                    .allocator = self.allocator,
                    .url = url,
                    .torrent = self.torrent,
                },
                .retries = 0,
            });
        }

        // Create shared result buffer
        var result_buffer = peer.Peers.init(self.allocator);

        // Mutex for result buffer
        var result_mutex = std.Thread.Mutex{};

        // One thread per tracker, up to 10.
        const num_threads = @min(4, self.torrent.metadata.announce_urls.len);

        // Allocate worker threads
        var threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        // Allocate worker contexts
        var contexts = try self.allocator.alloc(tracker.WorkerContext, num_threads);
        defer self.allocator.free(contexts);

        for (0..num_threads) |i| {
            contexts[i] = .{
                .queue = &tracker_queue,
                .torrent = self.torrent,
                .result_buffer = &result_buffer,
                .result_mutex = &result_mutex,
            };

            threads[i] = try std.Thread.spawn(.{}, tracker.workerThread, .{&contexts[i]});
        }

        while (true) {
            if (result_buffer.items.len > 1) {
                break;
            }

            std.time.sleep(10 * std.time.ns_per_ms);
        }

        // Wait for all threads to complete
        for (threads) |thread| {
            thread.join();
        }

        return result_buffer;
    }

    /// Downloads the whole torrent using multiple threads.
    pub fn download(self: *@This(), output_file: []const u8) !void {
        var peers = try self.getPeers();
        defer peers.deinit();

        var piece_queue = piece.Queue.init(self.allocator);
        defer piece_queue.deinit();

        // Fill queue with all piece indices
        for (0..self.torrent.metadata.info.pieces.len) |i| {
            try piece_queue.push(.{
                .index = @intCast(i),
                .retries = 0,
            });
        }

        // Create shared result buffer
        var result_buffer = std.ArrayList(piece.DownloadedPiece).init(self.allocator);
        defer {
            for (result_buffer.items) |p| {
                p.deinit(self.allocator);
            }
            result_buffer.deinit();
        }

        // Mutex for result buffer
        var result_mutex = std.Thread.Mutex{};

        // One thread per peer, up to X.
        const num_threads = @min(MAX_DOWNLOAD_THREADS, peers.items.len);

        // Allocate worker threads
        var threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        // Allocate worker contexts
        var contexts = try self.allocator.alloc(piece.WorkerContext, num_threads);
        defer self.allocator.free(contexts);

        for (0..num_threads) |i| {
            contexts[i] = .{
                .queue = &piece_queue,
                .peer = &peers.items[i],
                .torrent = self.torrent,
                .result_buffer = &result_buffer,
                .result_mutex = &result_mutex,
            };

            threads[i] = try std.Thread.spawn(.{}, piece.workerThread, .{&contexts[i]});
        }

        // Open output file in main thread
        const file = try std.fs.cwd().createFile(output_file, .{});
        defer file.close();

        // Keep track of downloaded pieces
        var downloaded_pieces: usize = 0;

        // Process completed pieces and write to file
        while (downloaded_pieces < self.torrent.metadata.info.pieces.len) {
            if (result_buffer.items.len > 0) {
                result_mutex.lock();
                const curr_piece = result_buffer.orderedRemove(0);
                defer self.allocator.free(curr_piece.data);
                result_mutex.unlock();

                std.debug.print("Writing piece: {}\n", .{curr_piece.index});

                // Write piece to file at correct offset
                try file.seekTo(curr_piece.index * self.torrent.metadata.info.piece_length);
                try file.writeAll(curr_piece.data);

                downloaded_pieces += 1;
            }

            std.time.sleep(10 * std.time.ns_per_ms);
        }

        std.debug.print("Downloaded all pieces. Terminating threads.\n", .{});

        // Wait for all threads to complete
        for (threads) |thread| {
            thread.join();
        }
    }
};
