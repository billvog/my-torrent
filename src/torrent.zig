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

const stdout = std.io.getStdOut().writer();

const bencode = @import("bencode.zig");
const utils = @import("utils.zig");

const TorrentMetadata = struct {
    announce: []const u8,
    created_by: ?[]const u8,
    info_hash: [sha1.digest_length]u8,
    info: struct {
        length: u64,
        name: []const u8,
        piece_length: u64,
        pieces: std.ArrayList([]const u8),
    },
};

const TorrentPeer = struct {
    ip: [4]u8,
    port: u16,

    pub fn toSlice(self: @This(), allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{ self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port });
    }
};

const TorrentPeers = std.ArrayList(TorrentPeer);

const TorrentHandshake = extern struct {
    protocol_length: u8 align(1) = 19,
    ident: [19]u8 align(1) = "BitTorrent protocol".*,
    reserved: [8]u8 align(1) = std.mem.zeroes([8]u8),
    info_hash: [20]u8 align(1),
    peer_id: [20]u8 align(1),
};

const ClientAbbreviation: []const u8 = "MT";
const ClientVersion = "0001";

pub const Torrent = struct {
    allocator: std.mem.Allocator,

    peer_id: [20]u8,

    file_path: []const u8,
    raw_data: []const u8,

    metadata: TorrentMetadata,

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !Torrent {
        const peer_id = try generatePeerId(allocator);

        const raw_data = try utils.readFileIntoString(allocator, file_path);

        var object: bencode.Object = bencode.Object.initFromString(allocator, raw_data) catch {
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
        self.allocator.free(self.raw_data);
        self.metadata.info.pieces.deinit();
    }

    fn generatePeerId(allocator: std.mem.Allocator) ![20]u8 {
        const random_string = try utils.generateRandomString(allocator, 12);
        defer allocator.free(random_string);

        var buffer: [20]u8 = undefined;
        _ = try std.fmt.bufPrint(&buffer, "-{s}{s}-{s}", .{ ClientAbbreviation, ClientVersion, random_string });
        return buffer;
    }

    /// Extracts the metadata from the root bencoded token of the .torrent file.
    fn metadataFromToken(allocator: std.mem.Allocator, token: bencode.Token) !TorrentMetadata {
        const dict = token.dictionary;
        const tracker_url = dict.get("announce") orelse return error.InvalidTorrentFile;
        const created_by = dict.get("created by");
        const info = dict.get("info") orelse return error.InvalidTorrentFile;

        const info_hash = try calculateTokenHash(allocator, info);
        const info_dict = info.dictionary;

        const length = info_dict.get("length") orelse return error.InvalidTorrentFile;
        const name = info_dict.get("name") orelse return error.InvalidTorrentFile;
        const piece_length = info_dict.get("piece length") orelse return error.InvalidTorrentFile;
        const pieces = info_dict.get("pieces") orelse return error.InvalidTorrentFile;

        var piece_list = std.ArrayList([]const u8).init(allocator);
        errdefer piece_list.deinit();

        var pieces_window = std.mem.window(u8, pieces.string, sha1.digest_length, sha1.digest_length);
        while (pieces_window.next()) |piece| {
            try piece_list.append(piece);
        }

        return TorrentMetadata{
            .announce = tracker_url.string,
            .created_by = if (created_by) |cb| cb.string else null,
            .info_hash = info_hash,
            .info = .{
                .name = name.string,
                .length = @as(u64, @intCast(length.integer)),
                .piece_length = @as(u64, @intCast(piece_length.integer)),
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

    pub fn getPeers(self: @This()) !TorrentPeers {
        // Fetch peers from the tracker.
        const response = try self.fetchPeers();
        defer response.deinit();

        // Parse the peers.
        const peer_list = try self.parsePeers(response);
        return peer_list;
    }

    /// Makes a GET request to the tracker URL to fetch peers.
    fn fetchPeers(self: @This()) !std.ArrayList(u8) {
        var client = http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Parse the tracker's URL.
        var uri = std.Uri.parse(self.metadata.announce) catch {
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
        try query.writer().print("&left={d}", .{self.metadata.info.length});
        try query.writer().print("&compact={d}", .{1});

        // Convert the query to a string.
        const query_str = try query.toOwnedSlice();
        defer self.allocator.free(query_str);

        // Append the query to the URI.
        uri.query = std.Uri.Component{ .raw = query_str };

        // Allocate a buffer to store the response.
        var response = std.ArrayList(u8).init(self.allocator);
        errdefer response.deinit();

        // Make the GET request.
        const request = try client.fetch(.{ .method = .GET, .location = .{ .uri = uri }, .response_storage = .{ .dynamic = &response } });
        if (request.status != .ok) {
            return error.TrackerRequestFailed;
        }

        return response;
    }

    /// Given the raw response from the tracker, parses the peers.
    fn parsePeers(self: @This(), raw_response: std.ArrayList(u8)) !TorrentPeers {
        // Decode response.
        const object = bencode.Object.initFromString(self.allocator, raw_response.items) catch {
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
        var peer_list = TorrentPeers.init(self.allocator);
        errdefer peer_list.deinit();

        var pieces_window = std.mem.window(u8, peers.string, 6, 6);
        while (pieces_window.next()) |piece| {
            var ip: [4]u8 = undefined;
            @memcpy(&ip, piece[0..4]);

            // Convert the port from big-endian to little-endian.
            const port = @as(u16, piece[4]) << 8 | piece[5];

            try peer_list.append(TorrentPeer{
                .ip = ip,
                .port = port,
            });
        }

        return peer_list;
    }

    /// Performs a handshake with the torrent.
    pub fn handshake(self: @This()) !void {
        // Get the peers.
        const peers = try self.getPeers();
        defer peers.deinit();

        var did_handshake = false;

        // Try and connect to a peer.
        for (peers.items) |peer| {
            const peer_str = try peer.toSlice(self.allocator);
            defer self.allocator.free(peer_str);

            std.debug.print("Handshake: Connecting to peer: {s}\n", .{peer_str});

            self.handshakeWithPeer(peer) catch |err| {
                std.debug.print("Handshake: Failed: {}\n", .{err});
                std.debug.print("Handshake: Trying next peer...\n", .{});
                continue;
            };

            // If we get successful handshake, break the loop.
            did_handshake = true;
            break;
        }

        if (!did_handshake) {
            return error.HandshakeFailed;
        }
    }

    /// Performs a handshake with a peer.
    fn handshakeWithPeer(self: @This(), peer: TorrentPeer) !void {
        const address = net.Address.initIp4(peer.ip, peer.port);

        var socket = try net.tcpConnectToAddress(address);
        defer socket.close();

        const writer = socket.writer();
        const reader = socket.reader();

        // Send the handshake message.
        try writer.writeStruct(TorrentHandshake{
            .info_hash = self.metadata.info_hash,
            .peer_id = self.peer_id,
        });

        // Receive the handshake response.
        const response_handshake = try reader.readStruct(TorrentHandshake);

        // Print peer's id.
        try stdout.print("Handshake: Peer Id: {s}\n", .{std.fmt.bytesToHex(response_handshake.peer_id, .lower)});
    }
};
