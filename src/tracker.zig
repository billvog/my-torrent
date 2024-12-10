const std = @import("std");

const Torrent = @import("torrent.zig").Torrent;
const peer = @import("peer.zig");
const udp = @import("udp.zig");
const utils = @import("utils.zig");
const bencode = @import("bencode.zig");

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

const TrackerPack = struct {
    tracker: Tracker,
    retries: u32,
};

pub const Queue = struct {
    mutex: std.Thread.Mutex,
    trackers: std.ArrayList(TrackerPack),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Queue {
        return .{
            .mutex = .{},
            .trackers = std.ArrayList(TrackerPack).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Queue) void {
        self.trackers.deinit();
    }

    pub fn push(self: *Queue, tracker: TrackerPack) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.trackers.append(tracker);
    }

    pub fn pop(self: *Queue) ?TrackerPack {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.trackers.items.len == 0) return null;
        return self.trackers.orderedRemove(0);
    }
};

pub const WorkerContext = struct {
    queue: *Queue,
    torrent: *Torrent,
    result_buffer: *std.ArrayList(peer.Peer),
    result_mutex: *std.Thread.Mutex,
};

pub fn workerThread(context: *WorkerContext) !void {
    while (true) {
        // Get next tracker from queue
        const pack = context.queue.pop() orelse break;
        const tracker = pack.tracker;

        std.debug.print("Connecting to tracker: {s}\n", .{tracker.url});

        // Fetch peers from tracker
        const peers = tracker.fetchPeers() catch |err| {
            std.debug.print("Error connecting to tracker: {s}: {}\n", .{ tracker.url, err });

            // If the url is invalid, or the protocol is not supported,
            // continue to the next tracker without re-queuing.
            switch (err) {
                error.InvalidURL,
                error.InvalidTrackerURL,
                error.UnsupportedTrackerProtocol,
                => {
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

        for (peers.items) |p| {
            context.result_buffer.append(p) catch {
                std.debug.print("Failed to append peer to result buffer\n", .{});
            };
        }
    }
}

pub const Tracker = struct {
    allocator: std.mem.Allocator,
    url: []const u8,
    torrent: *Torrent,

    pub fn fetchPeers(self: @This()) !peer.Peers {
        const url_split = utils.splitHostPort(self.url) catch {
            return error.InvalidURL;
        };

        if (std.mem.eql(u8, url_split.proto, "http") or std.mem.eql(u8, url_split.proto, "https")) {
            return try self.fetchPeersHttp(self.url);
        } else if (std.mem.eql(u8, url_split.proto, "udp")) {
            return try self.fetchPeersUDP(self.url);
        } else {
            return error.UnsupportedTrackerProtocol;
        }
    }

    fn fetchPeersUDP(self: @This(), announce: []const u8) !peer.Peers {
        const announce_split = utils.splitHostPort(announce) catch {
            return error.InvalidTrackerURL;
        };

        if (announce_split.port == null) {
            return error.InvalidTrackerURL;
        }

        const address_list = try std.net.getAddressList(self.allocator, announce_split.host, announce_split.port.?);
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
            .info_hash = self.torrent.metadata.info_hash,
            .peer_id = self.torrent.peer_id,
            .key = key,
            .event = 2,
            .downloaded = 0,
            .left = self.torrent.metadata.info.total_length,
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
        // var peers: [6 * 10]u8 = undefined;
        // _ = try reader.read(&peers);

        // std.debug.print("Peer: {s}\n", .{std.fmt.bytesToHex(peers, .lower)});

        return peer.Peers.init(self.allocator);
    }

    fn fetchPeersHttp(self: @This(), announce: []const u8) !peer.Peers {
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Parse the tracker's URL.
        var uri = std.Uri.parse(announce) catch {
            return error.InvalidTrackerURL;
        };

        // Build the query parameters.
        var query = std.ArrayList(u8).init(self.allocator);
        defer query.deinit();

        try query.writer().print("info_hash={s}", .{self.torrent.metadata.info_hash});
        try query.writer().print("&peer_id={s}", .{self.torrent.peer_id});
        try query.writer().print("&port={d}", .{6881});
        try query.writer().print("&uploaded={d}", .{0});
        try query.writer().print("&downloaded={d}", .{0});
        try query.writer().print("&left={d}", .{self.torrent.metadata.info.total_length});
        try query.writer().print("&compact={d}", .{1});

        // Convert the query to a string.
        const query_str = try query.toOwnedSlice();
        defer self.allocator.free(query_str);

        // Append the query to the URI.
        uri.query = std.Uri.Component{ .raw = query_str };

        // Allocate a buffer to store the response.
        var response = std.ArrayList(u8).init(self.allocator);
        defer response.deinit();

        std.debug.print("Attemping connection with tracker: {s}...\n", .{announce});

        // Make the GET request.
        const request = try client.fetch(.{ .method = .GET, .location = .{ .uri = uri }, .response_storage = .{ .dynamic = &response } });
        if (request.status != .ok) {
            return error.TrackerRequestFailed;
        }

        const peers = try self.parsePeers(response.items);
        return peers;
    }

    /// Given the raw response from the tracker, parses the peers.
    fn parsePeers(self: @This(), raw_response: []u8) !peer.Peers {
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
        const peers_token = object.root.dictionary.get("peers") orelse return error.InvalidTrackerResponse;

        // The peers key should be a string. We will parse it as a list of 6-byte strings.
        var peers = peer.Peers.init(self.allocator);
        errdefer peers.deinit();

        switch (peers_token) {
            .string => |peer_str| {
                var pieces_window = std.mem.window(u8, peer_str, 6, 6);
                while (pieces_window.next()) |piece| {
                    var ip: [4]u8 = undefined;
                    @memcpy(&ip, piece[0..4]);

                    // Convert the port from big-endian to little-endian.
                    const port = @as(u16, piece[4]) << 8 | piece[5];

                    try peers.append(peer.Peer{ .allocator = self.allocator, .ip = ip, .port = port, .peer_id = null, .torrent = self.torrent });
                }
            },
            .list => |peer_list| {
                for (peer_list.items) |peer_token| {
                    if (peer_token != .dictionary) {
                        return error.InvalidTrackerResponse;
                    }

                    const ip_token = peer_token.dictionary.get("ip") orelse return error.InvalidTrackerResponse;
                    const port_token = peer_token.dictionary.get("port") orelse return error.InvalidTrackerResponse;
                    const peer_id_token = peer_token.dictionary.get("peer id");

                    if (ip_token != .string or port_token != .integer) {
                        return error.InvalidTrackerResponse;
                    }

                    var ip: [4]u8 = undefined;
                    @memcpy(&ip, ip_token.string[0..4]);

                    const port = @as(u16, @intCast(port_token.integer));

                    var peer_id: [20]u8 = undefined;
                    if (peer_id_token) |id| {
                        if (id != .string) {
                            return error.InvalidTrackerResponse;
                        }

                        @memcpy(&peer_id, id.string[0..20]);
                    }

                    try peers.append(peer.Peer{
                        .allocator = self.allocator,
                        .ip = ip,
                        .port = port,
                        .peer_id = peer_id,
                        .torrent = self.torrent,
                    });
                }
            },
            else => return error.InvalidTrackerResponse,
        }

        return peers;
    }
};
