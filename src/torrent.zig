//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 30/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const sha1 = std.crypto.hash.Sha1;
const http = std.http;
const net = std.net;

const bencode = @import("bencode.zig");
const utils = @import("utils.zig");
const udp = @import("udp.zig");

const ClientAbbreviation: []const u8 = "MT";
const ClientVersion = "0001";

const MAX_TRACKER_RETRIES = 3;
const MAX_PIECE_RETRIES = 3;

const File = struct {
    path: []const u8,
    length: u32,
};

const Metadata = struct {
    announce_urls: [][]const u8,
    created_by: ?[]const u8,
    info_hash: [sha1.digest_length]u8,
    info: struct {
        files: std.ArrayList(File),
        total_length: u32,
        piece_length: u32,
        pieces: [][20]u8,
    },
};

const Peer = struct {
    ip: [4]u8,
    port: u16,

    pub fn toSlice(self: @This(), allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{ self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port });
    }
};

const Peers = std.ArrayList(Peer);

const Handshake = extern struct {
    protocol_length: u8 align(1) = 19,
    ident: [19]u8 align(1) = "BitTorrent protocol".*,
    reserved: [8]u8 align(1) = std.mem.zeroes([8]u8),
    info_hash: [20]u8 align(1),
    peer_id: [20]u8 align(1),
};

const TrackerConnectRequest = extern struct {
    protocol_id: u64 align(1) = 0x41727101980,
    action: u32 align(1) = 0,
    transaction_id: u32 align(1),
};

const TrackerConnectResponse = extern struct {
    action: u32 align(1),
    transaction_id: u32 align(1),
    connection_id: u64 align(1),
};

const TrackerAnnounceRequest = extern struct {
    connection_id: u64 align(1),
    action: u32 align(1) = 1,
    transaction_id: u32 align(1),
    info_hash: [20]u8 align(1),
    peer_id: [20]u8 align(1),
    downloaded: u64 align(1),
    left: u64 align(1),
    uploaded: u64 align(1),
    event: u32 align(1) = 0,
    ip: u32 align(1) = 0,
    key: u32 align(1) = 0,
    num_want: i32 align(1) = -1,
    port: u16 align(1),
};

const TrackerAnnounceResponse = extern struct {
    action: u32 align(1),
    transaction_id: u32 align(1),
    interval: u32 align(1),
    leechers: u32 align(1),
    seeders: u32 align(1),
};

const PeerMessageType = enum(u8) {
    choke = 0,
    unchoke = 1,
    interested = 2,
    not_interested = 3,
    have = 4,
    bitfield = 5,
    request = 6,
    piece = 7,
    cancel = 8,
};

const PeerMessage = union(PeerMessageType) {
    choke,
    unchoke,
    interested,
    not_interested,
    have,
    bitfield,
    request: Request,
    piece: Piece,
    cancel,

    const Request = struct {
        index: u32,
        begin: u32,
        length: u32,
    };

    const Piece = struct {
        index: u32,
        begin: u32,
        block: []u8,
    };

    fn deinit(self: @This(), alloc: std.mem.Allocator) void {
        if (self == .piece) {
            alloc.free(self.piece.block);
        }
    }

    fn read(allocator: std.mem.Allocator, reader: std.io.AnyReader) !PeerMessage {
        var len: u32 = 0;

        // Skip keep-alive messages.
        while (len == 0) {
            len = try reader.readInt(u32, .big);
        }

        const message_id = try reader.readEnum(PeerMessageType, .big);
        len -= 1;

        switch (message_id) {
            inline .choke, .unchoke, .interested, .not_interested, .bitfield, .have, .cancel => |msg| {
                try reader.skipBytes(len, .{});
                return msg;
            },
            .piece => {
                if (len < 8) {
                    return error.InvalidMessage;
                }

                const index = try reader.readInt(u32, .big);
                const begin = try reader.readInt(u32, .big);
                len -= @sizeOf(u32) * 2;

                const block = try allocator.alloc(u8, len);
                errdefer allocator.free(block);

                _ = try reader.readAll(block);

                return .{ .piece = .{
                    .index = index,
                    .begin = begin,
                    .block = block,
                } };
            },
            else => return error.NotImplemented,
        }
    }

    fn write(self: @This(), writer: std.io.AnyWriter) !void {
        switch (self) {
            .interested, .not_interested => {
                try writer.writeInt(u32, 1, .big);
                try writer.writeByte(@intFromEnum(self));
            },
            .request => |r| {
                try writer.writeInt(u32, @sizeOf(Request) + 1, .big);
                try writer.writeByte(@intFromEnum(self));
                try writer.writeInt(u32, r.index, .big);
                try writer.writeInt(u32, r.begin, .big);
                try writer.writeInt(u32, r.length, .big);
            },
            else => {
                return error.NotImplemented;
            },
        }
    }
};

const TrackerInfo = struct {
    url: []const u8,
    retries: u32,
};

const TrackerQueue = struct {
    mutex: std.Thread.Mutex,
    trackers: std.ArrayList(TrackerInfo),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) TrackerQueue {
        return .{
            .mutex = .{},
            .trackers = std.ArrayList(TrackerInfo).init(allocator),
            .allocator = allocator,
        };
    }

    fn deinit(self: *TrackerQueue) void {
        self.trackers.deinit();
    }

    fn push(self: *TrackerQueue, tracker: TrackerInfo) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.trackers.append(tracker);
    }

    fn pop(self: *TrackerQueue) ?TrackerInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.trackers.items.len == 0) return null;
        return self.trackers.orderedRemove(0);
    }
};

const TrackerWorkerContext = struct {
    queue: *TrackerQueue,
    torrent: *Torrent,
    result_buffer: *std.ArrayList(Peer),
    result_mutex: *std.Thread.Mutex,
};

fn trackerWorkerThread(context: *TrackerWorkerContext) !void {
    while (true) {
        // Get next tracker from queue
        const tracker = context.queue.pop() orelse break;

        std.debug.print("Connecting to tracker: {s}\n", .{tracker.url});

        // Fetch peers from tracker
        const peers = context.torrent.fetchPeers(tracker.url) catch |err| {
            std.debug.print("Error connecting to tracker: {s}: {}\n", .{ tracker.url, err });

            // If the url is invalid, or the protocol is not supported,
            // continue to the next tracker without re-queuing.
            switch (err) {
                error.InvalidTrackerURL, error.UnsupportedTrackerProtocol => {
                    continue;
                },
                else => {},
            }

            // Re-queue if under max retries
            // if (tracker.retries < MAX_TRACKER_RETRIES) {
            //     context.queue.push(.{
            //         .url = tracker.url,
            //         .retries = tracker.retries + 1,
            //     }) catch {
            //         std.debug.print("Failed to re-queue tracker {s}\n", .{tracker.url});
            //     };
            // } else {
            //     std.debug.print("Tracker {s} failed after {} retries\n", .{ tracker.url, MAX_TRACKER_RETRIES });
            // }

            // Continue to next tracker
            continue;
        };
        defer peers.deinit();

        // Store the result
        context.result_mutex.lock();
        defer {
            context.result_mutex.unlock();
            std.time.sleep(100 * std.time.ns_per_ms);
        }

        for (peers.items) |peer| {
            context.result_buffer.append(peer) catch {
                std.debug.print("Failed to append peer to result buffer\n", .{});
            };
        }
    }
}

const PieceInfo = struct {
    index: u32,
    retries: u32,
};

// Thread-safe queue for piece tasks
const PieceQueue = struct {
    mutex: std.Thread.Mutex,
    pieces: std.ArrayList(PieceInfo),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) PieceQueue {
        return .{
            .mutex = .{},
            .pieces = std.ArrayList(PieceInfo).init(allocator),
            .allocator = allocator,
        };
    }

    fn deinit(self: *PieceQueue) void {
        self.pieces.deinit();
    }

    fn push(self: *PieceQueue, piece: PieceInfo) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.pieces.append(piece);
    }

    fn pop(self: *PieceQueue) ?PieceInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.pieces.items.len == 0) return null;
        return self.pieces.orderedRemove(0);
    }
};

const DownloadedPiece = struct {
    index: u32,
    data: []u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

const PieceWorkerContext = struct {
    queue: *PieceQueue,
    torrent: *Torrent,
    result_buffer: *std.ArrayList(DownloadedPiece),
    result_mutex: *std.Thread.Mutex,
    peer: Peer,
    stream: ?net.Stream = null,
};

fn pieceWorkerThread(context: *PieceWorkerContext) void {
    context.stream = context.torrent.initPeer(context.peer) catch |err| {
        std.debug.print("Failed to init peer: {}\n", .{err});
        return;
    };
    defer context.stream.?.close();

    while (true) {
        // Get next piece from queue
        const piece_info = context.queue.pop() orelse break;

        // Download the piece
        const piece_data = context.torrent.downloadPiece(&context.stream.?, piece_info.index) catch |err| {
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

        // Store the result
        context.result_mutex.lock();
        defer context.result_mutex.unlock();

        context.result_buffer.append(.{
            .index = piece_info.index,
            .data = piece_data,
        }) catch continue;
    }
}

pub const Torrent = struct {
    allocator: std.mem.Allocator,

    peer_id: [20]u8,

    file_path: []const u8,
    raw_data: []const u8,

    metadata: Metadata,

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !Torrent {
        const peer_id = try generatePeerId(allocator);

        const raw_data = try utils.readFileIntoString(allocator, file_path);

        var object: bencode.Object = bencode.Object.initFromString(allocator, raw_data) catch |err| {
            std.debug.print("Error: {}\n", .{err});
            return error.InvalidTorrentFile;
        };
        defer object.deinit();

        const metadata = try metadataFromToken(allocator, object.root);

        return Torrent{
            .allocator = allocator,
            .peer_id = peer_id,
            .file_path = file_path,
            .raw_data = raw_data,
            .metadata = metadata,
        };
    }

    pub fn deinit(self: @This()) void {
        for (self.metadata.info.files.items) |file| {
            self.allocator.free(file.path);
        }
        self.metadata.info.files.deinit();

        self.allocator.free(self.raw_data);

        self.allocator.free(self.metadata.announce_urls);
        self.allocator.free(self.metadata.info.pieces);
    }

    fn generatePeerId(allocator: std.mem.Allocator) ![20]u8 {
        const random_string = try utils.generateRandomString(allocator, 12);
        defer allocator.free(random_string);

        var buffer: [20]u8 = undefined;
        _ = try std.fmt.bufPrint(&buffer, "-{s}{s}-{s}", .{ ClientAbbreviation, ClientVersion, random_string });
        return buffer;
    }

    /// Extracts the metadata from the root bencoded token of the .torrent file.
    fn metadataFromToken(allocator: std.mem.Allocator, token: bencode.Token) !Metadata {
        const dict = token.dictionary;

        var announce_urls = std.ArrayList([]const u8).init(allocator);
        defer announce_urls.deinit();

        const announce = dict.get("announce") orelse return error.InvalidTorrentFile;
        if (announce != .string) {
            return error.InvalidTorrentFile;
        }

        try announce_urls.append(announce.string);

        const announce_list = dict.get("announce-list");
        if (announce_list) |list| {
            if (list != .list) {
                return error.InvalidTorrentFile;
            }

            for (list.list.items) |item| {
                if (item != .list) {
                    return error.InvalidTorrentFile;
                }

                for (item.list.items) |url| {
                    if (url != .string) {
                        return error.InvalidTorrentFile;
                    }

                    // Skip duplicates
                    if (std.mem.eql(u8, url.string, announce.string)) {
                        continue;
                    }

                    try announce_urls.append(url.string);
                }
            }
        }

        const created_by = dict.get("created by");
        const info = dict.get("info") orelse return error.InvalidTorrentFile;

        const info_hash = try calculateTokenHash(allocator, info);
        const info_dict = info.dictionary;

        var files = std.ArrayList(File).init(allocator);

        const files_token = info_dict.get("files");
        if (files_token) |files_list| {
            for (files_list.list.items) |file| {
                const file_dict = file.dictionary;
                const path = file_dict.get("path") orelse return error.InvalidTorrentFile;
                const length = file_dict.get("length") orelse return error.InvalidTorrentFile;

                var assembled_path = std.ArrayList(u8).init(allocator);
                defer assembled_path.deinit();

                for (path.list.items, 0..) |path_element, i| {
                    if (path_element != .string) {
                        return error.InvalidTorrentFile;
                    }

                    try assembled_path.appendSlice(path_element.string);
                    if (i < path.list.items.len - 1) {
                        try assembled_path.append('/');
                    }
                }

                try files.append(File{
                    .path = try assembled_path.toOwnedSlice(),
                    .length = @as(u32, @intCast(length.integer)),
                });
            }
        } else {
            const name = info_dict.get("name") orelse return error.InvalidTorrentFile;
            const length = info_dict.get("length") orelse return error.InvalidTorrentFile;

            try files.append(File{
                .path = name.string,
                .length = @as(u32, @intCast(length.integer)),
            });
        }

        var total_length: u32 = 0;
        for (files.items) |file| {
            total_length += file.length;
        }

        const piece_length = info_dict.get("piece length") orelse return error.InvalidTorrentFile;
        const pieces = info_dict.get("pieces") orelse return error.InvalidTorrentFile;

        const pieces_num = pieces.string.len / sha1.digest_length;

        var piece_list: [][sha1.digest_length]u8 = try allocator.alloc([20]u8, pieces_num);
        errdefer allocator.free(piece_list);

        for (0..pieces_num) |i| {
            const start = i * sha1.digest_length;
            const end = start + sha1.digest_length;
            @memcpy(&piece_list[i], pieces.string[start..end]);
        }

        return Metadata{
            .announce_urls = try announce_urls.toOwnedSlice(),
            .created_by = if (created_by) |cb| cb.string else null,
            .info_hash = info_hash,
            .info = .{
                .files = files,
                .total_length = total_length,
                .piece_length = @as(u32, @intCast(piece_length.integer)),
                .pieces = piece_list,
            },
        };
    }

    /// Calculates the SHA-1 hash of the bencoded info dictionary.
    fn calculateTokenHash(allocator: std.mem.Allocator, info_token: bencode.Token) ![sha1.digest_length]u8 {
        const token_bytes = try bencode.encodeToken(allocator, info_token);
        defer allocator.free(token_bytes);

        var hash: [sha1.digest_length]u8 = undefined;
        sha1.hash(token_bytes, &hash, .{});

        return hash;
    }

    /// Fetches peers from trackers, using multiple threads.
    pub fn getPeers(self: *@This()) !Peers {
        var tracker_queue = TrackerQueue.init(self.allocator);
        defer tracker_queue.deinit();

        // Fill queue with all piece indices
        for (self.metadata.announce_urls) |url| {
            try tracker_queue.push(.{
                .url = url,
                .retries = 0,
            });
        }

        // Create shared result buffer
        var result_buffer = std.ArrayList(Peer).init(self.allocator);

        // Mutex for result buffer
        var result_mutex = std.Thread.Mutex{};

        // One thread per tracker, up to 10.
        const num_threads = @min(4, self.metadata.announce_urls.len);

        // Allocate worker threads
        var threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        // Allocate worker contexts
        var contexts = try self.allocator.alloc(TrackerWorkerContext, num_threads);
        defer self.allocator.free(contexts);

        for (0..num_threads) |i| {
            contexts[i] = .{
                .queue = &tracker_queue,
                .torrent = self,
                .result_buffer = &result_buffer,
                .result_mutex = &result_mutex,
            };

            threads[i] = try std.Thread.spawn(.{}, trackerWorkerThread, .{&contexts[i]});
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

    /// Connects to the tracker and fetches the peers.
    fn fetchPeers(self: @This(), announce: []const u8) !Peers {
        const url_split = utils.splitHostPort(announce) catch {
            return error.InvalidTrackerURL;
        };

        if (std.mem.eql(u8, url_split.proto, "http")) {
            return try self.fetchPeersHttp(announce);
        } else if (std.mem.eql(u8, url_split.proto, "udp")) {
            return try self.fetchPeersUDP(announce);
        } else {
            return error.UnsupportedTrackerProtocol;
        }
    }

    fn fetchPeersUDP(self: @This(), announce: []const u8) !Peers {
        const announce_split = utils.splitHostPort(announce) catch {
            return error.InvalidTrackerURL;
        };

        if (announce_split.port == null) {
            return error.InvalidTrackerURL;
        }

        const address_list = try net.getAddressList(self.allocator, announce_split.host, announce_split.port.?);
        defer address_list.deinit();

        const address = address_list.addrs[0];

        var stream = try udp.udpConnectToAddress(address);
        defer stream.close();

        const writer = stream.writer();
        const reader = stream.reader();

        std.debug.print("Attemping connection with tracker: {s}...\n", .{announce});

        var transaction_id = std.crypto.random.int(u32);

        // Send connect request.
        try writer.writeStructEndian(TrackerConnectRequest{ .transaction_id = transaction_id }, .big);

        // Receive connect response.
        const response = try reader.readStructEndian(TrackerConnectResponse, .big);
        if (response.transaction_id != transaction_id or response.action != 0) {
            return error.InvalidTrackerResponse;
        }

        std.debug.print("Connected to tracker:\n", .{});
        std.debug.print("  Tracker: {s}\n", .{announce});
        std.debug.print("  Connection ID: {}\n", .{response.connection_id});

        transaction_id = std.crypto.random.int(u32);
        const key = std.crypto.random.int(u32);

        // Send announce request.
        try writer.writeStructEndian(TrackerAnnounceRequest{
            .connection_id = response.connection_id,
            .transaction_id = transaction_id,
            .info_hash = self.metadata.info_hash,
            .peer_id = self.peer_id,
            .key = key,
            .event = 2,
            .downloaded = 0,
            .left = self.metadata.info.total_length,
            .uploaded = 0,
            .port = 6881,
            .num_want = 10,
        }, .big);

        // Receive announce response.
        const announce_response = try reader.readStructEndian(TrackerAnnounceResponse, .big);
        if (announce_response.transaction_id != transaction_id or announce_response.action != 1) {
            return error.InvalidTrackerResponse;
        }

        const seeders = announce_response.seeders;

        std.debug.print("Announce:\n", .{});
        std.debug.print("  Tracker: {s}\n", .{announce});
        std.debug.print("  Interval: {}\n", .{announce_response.interval});
        std.debug.print("  Seeders: {}\n", .{seeders});

        // Read peers.
        var peers: [6 * 10]u8 = undefined;
        _ = try reader.read(&peers);

        std.debug.print("Peer: {s}\n", .{std.fmt.bytesToHex(peers, .lower)});

        return std.ArrayList(Peer).init(self.allocator);
    }

    fn fetchPeersHttp(self: @This(), announce: []const u8) !Peers {
        var client = http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Parse the tracker's URL.
        var uri = std.Uri.parse(announce) catch {
            return error.InvalidTrackerURL;
        };

        // Build the query parameters.
        var query = std.ArrayList(u8).init(self.allocator);
        defer query.deinit();

        try query.writer().print("info_hash={s}", .{self.metadata.info_hash});
        try query.writer().print("&peer_id={s}", .{self.peer_id});
        try query.writer().print("&port={d}", .{6881});
        try query.writer().print("&uploaded={d}", .{0});
        try query.writer().print("&downloaded={d}", .{0});
        try query.writer().print("&left={d}", .{self.metadata.info.total_length});
        try query.writer().print("&compact={d}", .{1});

        // Convert the query to a string.
        const query_str = try query.toOwnedSlice();
        defer self.allocator.free(query_str);

        // Append the query to the URI.
        uri.query = std.Uri.Component{ .raw = query_str };

        // Allocate a buffer to store the response.
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        std.debug.print("Fetching peers from tracker: {s}...\n", .{announce});

        // Make the GET request.
        const request = try client.fetch(.{ .method = .GET, .location = .{ .uri = uri }, .response_storage = .{ .dynamic = &response } });
        if (request.status != .ok) {
            return error.TrackerRequestFailed;
        }

        const peers = try self.parsePeers(response.items);
        return peers;
    }

    /// Given the raw response from the tracker, parses the peers.
    fn parsePeers(self: @This(), raw_response: []u8) !Peers {
        // Decode response.
        const object = bencode.Object.initFromString(self.allocator, raw_response) catch {
            return error.InvalidTrackerResponse;
        };
        defer object.deinit();

        // It should be a dictionary.
        if (object.root != .dictionary) {
            return error.InvalidTrackerResponse;
        }

        // Extract the peers key from the dict.
        const peers = object.root.dictionary.get("peers") orelse return error.InvalidTrackerResponse;

        // The peers key should be a string. We will parse it as a list of 6-byte strings.
        var peer_list = Peers.init(self.allocator);
        errdefer peer_list.deinit();

        var pieces_window = std.mem.window(u8, peers.string, 6, 6);
        while (pieces_window.next()) |piece| {
            var ip: [4]u8 = undefined;
            @memcpy(&ip, piece[0..4]);

            // Convert the port from big-endian to little-endian.
            const port = @as(u16, piece[4]) << 8 | piece[5];

            try peer_list.append(Peer{
                .ip = ip,
                .port = port,
            });
        }

        return peer_list;
    }

    /// Performs a handshake with the torrent.
    pub fn handshake(self: *@This()) !net.Stream {
        // Get the peers.
        const peers = try self.getPeers();
        defer peers.deinit();

        // Try and connect to a peer.
        for (peers.items) |peer| {
            const peer_str = try peer.toSlice(self.allocator);
            defer self.allocator.free(peer_str);

            std.debug.print("Handshake: Connecting to peer: {s}\n", .{peer_str});

            var stream = self.handshakeWithPeer(peer) catch |err| {
                std.debug.print("Handshake: Failed: {}\n", .{err});
                std.debug.print("Handshake: Trying next peer...\n", .{});
                continue;
            };
            errdefer stream.close();

            // We had a successful handshake.
            return stream;
        }

        return error.HandshakeFailed;
    }

    /// Performs a handshake with a peer.
    fn handshakeWithPeer(self: @This(), peer: Peer) !net.Stream {
        const address = net.Address.initIp4(peer.ip, peer.port);

        var stream = try net.tcpConnectToAddress(address);
        errdefer stream.close();

        const writer = stream.writer();
        const reader = stream.reader();

        // Send the handshake message.
        try writer.writeStruct(Handshake{
            .info_hash = self.metadata.info_hash,
            .peer_id = self.peer_id,
        });

        // Receive the handshake response.
        const response_handshake = try reader.readStruct(Handshake);

        // Print peer's id.
        std.debug.print("Handshake: Peer Id: {s}\n", .{std.fmt.bytesToHex(response_handshake.peer_id, .lower)});

        return stream;
    }

    /// Downloads the whole torrent using multiple threads.
    pub fn download(self: *@This(), output_file: []const u8) !void {
        var peers = try self.getPeers();
        defer peers.deinit();

        var piece_queue = PieceQueue.init(self.allocator);
        defer piece_queue.deinit();

        // Fill queue with all piece indices
        for (0..self.metadata.info.pieces.len) |i| {
            try piece_queue.push(.{
                .index = @intCast(i),
                .retries = 0,
            });
        }

        // Create shared result buffer
        var result_buffer = std.ArrayList(DownloadedPiece).init(self.allocator);
        defer {
            for (result_buffer.items) |piece| {
                piece.deinit(self.allocator);
            }
            result_buffer.deinit();
        }

        // Mutex for result buffer
        var result_mutex = std.Thread.Mutex{};

        // One thread per peer
        const num_threads = peers.items.len;

        // Allocate worker threads
        var threads = try self.allocator.alloc(std.Thread, num_threads);
        defer self.allocator.free(threads);

        // Allocate worker contexts
        var contexts = try self.allocator.alloc(PieceWorkerContext, num_threads);
        defer self.allocator.free(contexts);

        for (0..num_threads) |i| {
            contexts[i] = .{
                .queue = &piece_queue,
                .torrent = self,
                .result_buffer = &result_buffer,
                .result_mutex = &result_mutex,
                .peer = peers.items[i],
            };

            threads[i] = try std.Thread.spawn(.{}, pieceWorkerThread, .{&contexts[i]});
        }

        // Open output file in main thread
        const file = try std.fs.cwd().createFile(output_file, .{});
        defer file.close();

        // Keep track of downloaded pieces
        var downloaded_pieces: usize = 0;

        // Process completed pieces and write to file
        while (downloaded_pieces < self.metadata.info.pieces.len) {
            if (result_buffer.items.len > 0) {
                result_mutex.lock();
                const piece = result_buffer.orderedRemove(0);
                defer self.allocator.free(piece.data);
                result_mutex.unlock();

                std.debug.print("Writing piece: {}\n", .{piece.index});

                // Write piece to file at correct offset
                try file.seekTo(piece.index * self.metadata.info.piece_length);
                try file.writeAll(piece.data);

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

    /// Makes a handshake and sends initial requests to the peer.
    fn initPeer(self: @This(), peer: Peer) !net.Stream {
        // Make a handshake with the peer.
        const stream = try self.handshakeWithPeer(peer);
        errdefer stream.close();

        const writer = stream.writer().any();
        const reader = stream.reader().any();

        {
            // Wait for bitfield message.
            const message = try PeerMessage.read(self.allocator, reader);
            defer message.deinit(self.allocator);
            if (message != .bitfield) {
                return error.UnexpectedMessageExpectedBitfield;
            }
        }

        // Send interested message.
        const interested_message: PeerMessage = .interested;
        defer interested_message.deinit(self.allocator);
        try interested_message.write(writer);

        {
            // Wait for unchoke message.
            const message = try PeerMessage.read(self.allocator, reader);
            defer message.deinit(self.allocator);
            if (message != .unchoke) {
                return error.UnexpectedMessageExpectedUnchoke;
            }
        }

        return stream;
    }

    /// Download a piece of the torrent.
    fn downloadPiece(self: @This(), stream: *net.Stream, piece_index: u32) ![]u8 {
        // Calculate the piece's length.
        var piece_length = self.metadata.info.piece_length;
        if (piece_index == self.metadata.info.pieces.len - 1) {
            piece_length = @rem(self.metadata.info.total_length, self.metadata.info.piece_length);
        }

        const piece_buf = try self.allocator.alloc(u8, piece_length);
        errdefer self.allocator.free(piece_buf);

        // Download the full piece.
        try self.requestPieceBlocks(stream, piece_index, piece_buf, self.metadata.info.pieces[piece_index]);

        return piece_buf;
    }

    /// Request blocks of a piece from the peer, and verify the hash.
    fn requestPieceBlocks(self: @This(), stream: *net.Stream, piece_index: u32, piece_buf: []u8, piece_hash: [sha1.digest_length]u8) !void {
        const writer = stream.writer().any();
        const reader = stream.reader().any();

        var begin: u32 = 0;
        const block_size = @min(16 * 1024, piece_buf.len);

        std.debug.print("Downloading piece: {} -- block: {}\n", .{ piece_index, block_size });

        while (begin < piece_buf.len) : (begin += block_size) {
            // Send request for block.
            const cur_block_len = @min(block_size, piece_buf.len - begin);
            const request: PeerMessage = .{ .request = .{ .index = piece_index, .begin = begin, .length = cur_block_len } };
            try request.write(writer);

            std.debug.print("Requested block for piece: {} -- begin: {} -- length: {}\n", .{ piece_index, begin, cur_block_len });

            // Receive the block.
            const response: PeerMessage = try PeerMessage.read(self.allocator, reader);
            defer response.deinit(self.allocator);
            if (response != .piece) {
                return error.UnexpectedMessageExpectedPiece;
            }

            // Add leading space to align with 'requested block' log above.
            std.debug.print(" Received block for piece: {}\n", .{piece_index});

            // Verify it's the one we requested.
            if (begin != response.piece.begin or cur_block_len != response.piece.block.len) {
                return error.InvalidPieceBlock;
            }

            // Copy the block to the piece buffer.
            @memcpy(piece_buf[begin .. begin + cur_block_len], response.piece.block);
        }

        // Once the piece is downloaded, verify the hash.
        var hash: [sha1.digest_length]u8 = undefined;
        sha1.hash(piece_buf, &hash, .{});

        if (std.mem.eql(u8, &hash, &piece_hash) == false) {
            return error.InvalidPieceHash;
        }

        std.debug.print("Downloaded piece: {}\n", .{piece_index});
    }
};
