//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 12/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();

const Torrent = @import("torrent.zig").Torrent;
const tracker = @import("tracker.zig");
const peer = @import("peer.zig");
const piece = @import("piece.zig");
const downloader = @import("downloader.zig");
const progress = @import("client_progress.zig");

const MAX_TRACKER_THREADS = 4;
const MAX_DOWNLOAD_THREADS = 50;

const FileHandle = struct {
    file: std.fs.File,
    path: []const u8,
};

const FileHandles = std.AutoHashMap(usize, FileHandle);

pub const Client = struct {
    allocator: std.mem.Allocator,
    torrent: *Torrent,

    pub fn init(allocator: std.mem.Allocator, torrent: *Torrent) Client {
        return .{ .allocator = allocator, .torrent = torrent };
    }

    /// Fetches peers from trackers, using multiple threads.
    pub fn getPeers(self: *@This()) !peer.Peers {
        var tracker_queue = tracker.TrackerQueue.init(self.allocator);
        defer tracker_queue.deinit();

        // Fill the queue with all tracker URLs
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

        // Create shared result buffer, and mutex
        var result_buffer = peer.Peers.init(self.allocator);
        var result_mutex = std.Thread.Mutex{};

        var should_stop = std.atomic.Value(bool).init(false);

        // One thread per tracker, up to X.
        const num_threads = @min(MAX_TRACKER_THREADS, self.torrent.metadata.announce_urls.len);

        // Allocate worker threads
        var threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        // Allocate worker contexts
        var contexts = try self.allocator.alloc(tracker.TrackerWorkerContext, num_threads);
        defer self.allocator.free(contexts);

        for (0..num_threads) |i| {
            contexts[i] = .{
                .queue = &tracker_queue,
                .torrent = self.torrent,
                .result_buffer = &result_buffer,
                .result_mutex = &result_mutex,
                .should_stop = &should_stop,
            };

            threads[i] = try std.Thread.spawn(.{}, tracker.trackerWorkerThread, .{&contexts[i]});
        }

        while (true) {
            defer std.time.sleep(10 * std.time.ns_per_ms);

            // If we find at least on peer stop.
            if (result_buffer.items.len > 1) {
                should_stop.store(true, .release);
                break;
            }
        }

        std.log.debug("Found a total of {} peers. Terminating threads.", .{result_buffer.items.len});

        return result_buffer;
    }

    /// Downloads the whole torrent using multiple threads.
    pub fn download(self: *@This(), output_folder: []const u8) !void {
        // var peers = try self.getPeers();
        // defer peers.deinit();

        const my_tracker = tracker.Tracker{
            .allocator = self.allocator,
            .url = "udp://tracker.opentrackr.org:1337",
            .torrent = self.torrent,
        };

        var peers = try my_tracker.fetchPeers();
        defer peers.deinit();

        std.log.debug("Received {d} peers. Continue with downloading...", .{peers.items.len});

        var peer_queue = downloader.PeerQueue.init(self.allocator);
        defer peer_queue.deinit();

        for (peers.items) |*p| {
            try peer_queue.push(p);
        }

        var piece_queue = downloader.DownloadQueue.init(self.allocator);
        defer piece_queue.deinit();

        // Fill queue with all piece indices
        for (0..self.torrent.metadata.info.pieces.len) |i| {
            try piece_queue.push(.{ .index = @intCast(i) });
        }

        // Create shared result buffer
        var result_buffer = std.ArrayList(downloader.DownloadedPiece).init(self.allocator);
        defer {
            for (result_buffer.items) |p| {
                p.deinit(self.allocator);
            }
            result_buffer.deinit();
        }

        // Mutex for result buffer
        var result_mutex = std.Thread.Mutex{};

        // Control variable to stop threads
        var should_stop = std.atomic.Value(bool).init(false);

        // One thread per peer, up to X.
        const num_threads = @as(usize, @min(MAX_DOWNLOAD_THREADS, peers.items.len));

        // Allocate downloaders
        var downloaders = try std.ArrayList(*downloader.Downloader).initCapacity(self.allocator, num_threads);
        defer {
            for (downloaders.items) |d| {
                d.deinit();
            }
            downloaders.deinit();
        }

        // Start download threads
        for (0..downloaders.capacity) |_| {
            try downloaders.append(try downloader.Downloader.init(
                self.allocator,
                &result_mutex,
                &peer_queue,
                &piece_queue,
                &result_buffer,
                &should_stop,
                self.torrent,
            ));
        }

        // Open file handles
        var file_handles = try self.initFileHandles(output_folder);
        defer self.deinitFileHandles(&file_handles);

        // Keep track of downloaded pieces
        var downloaded_pieces = std.atomic.Value(usize).init(0);
        // Keep track of connected peers
        var connected_peers = std.atomic.Value(usize).init(0);

        // Start progress thread
        const client_progress = try progress.ClientProgress.init(
            self.allocator,
            &downloaded_pieces,
            &self.torrent.metadata.info.pieces.len,
            &connected_peers,
            &should_stop,
        );

        defer {
            client_progress.deinit();
            stdout.print("\nDownload is ready! Exiting...\n", .{}) catch {
                std.log.err("Error printing download is ready message.", .{});
            };
        }

        // Process completed pieces and write to file
        while (!should_stop.load(.monotonic)) {
            // Sleep for some time between iterations
            defer std.time.sleep(10 * std.time.ns_per_ms);

            // Count connected peers
            var tmp_connected_peers: usize = 0;
            for (downloaders.items) |d| {
                if (d.is_connected.load(.monotonic)) {
                    tmp_connected_peers += 1;
                }
            }
            connected_peers.store(tmp_connected_peers, .release);

            // Skip if no items in result buffer
            if (result_buffer.items.len == 0) {
                continue;
            }

            // Pop piece from result buffer
            result_mutex.lock();
            const curr_piece = result_buffer.orderedRemove(0);
            defer self.allocator.free(curr_piece.data);
            result_mutex.unlock();

            std.log.debug("Writing piece: {}", .{curr_piece.index});

            // Try to write piece to disk
            self.writePieceToDisk(&file_handles, &curr_piece) catch |err| {
                std.log.err("Error writing piece to disk: {}", .{err});

                result_mutex.lock();
                defer result_mutex.unlock();

                // Re-queue piece
                result_buffer.append(curr_piece) catch {
                    std.log.err("Error re-queueing piece: {}", .{curr_piece.index});
                };

                continue;
            };

            // On success, increment downloaded pieces
            _ = downloaded_pieces.fetchAdd(1, .release);
            if (downloaded_pieces.load(.monotonic) == self.torrent.metadata.info.pieces.len) {
                should_stop.store(true, .release);
            }
        }
    }

    /// Initializes file handles for all files in the torrent, and creates parent directories if needed.
    fn initFileHandles(self: @This(), output_folder: []const u8) !FileHandles {
        var file_handles = FileHandles.init(self.allocator);
        errdefer file_handles.deinit();

        for (self.torrent.metadata.info.files.items, 0..) |file, i| {
            const path = try std.fs.path.join(self.allocator, &[_][]const u8{ output_folder, file.path });
            defer self.allocator.free(path);

            // Create file and parent directories
            if (std.fs.path.dirname(path)) |dir| {
                try std.fs.cwd().makePath(dir);
            }

            const file_handle = try std.fs.cwd().createFile(path, .{});
            errdefer file_handle.close();

            try file_handle.setEndPos(file.length);

            try file_handles.put(i, .{
                .file = file_handle,
                .path = try self.allocator.dupe(u8, path),
            });
        }

        return file_handles;
    }

    /// Closes all file handles and frees memory.
    fn deinitFileHandles(self: @This(), file_handles: *FileHandles) void {
        var iterator = file_handles.iterator();
        while (iterator.next()) |entry| {
            self.allocator.free(entry.value_ptr.path);
            entry.value_ptr.file.close();
        }
        file_handles.deinit();
    }

    /// Writes a downloaded piece to disk, handling multiple file spans.
    fn writePieceToDisk(self: @This(), file_handles: *FileHandles, downloaded_piece: *const downloader.DownloadedPiece) !void {
        const spans = try piece.getPieceFileSpans(self.allocator, self.torrent, downloaded_piece.index);
        defer self.allocator.free(spans);

        for (spans) |span| {
            const file_handle = file_handles.get(span.file_index);
            if (file_handle == null) {
                std.log.err("File handle not found for index: {}", .{span.file_index});
                continue;
            }

            try file_handle.?.file.seekTo(span.file_offset);
            try file_handle.?.file.writeAll(downloaded_piece.data[span.piece_offset .. span.piece_offset + span.length]);
        }
    }
};
