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

const Metadata = struct {
    announce: []const u8,
    created_by: ?[]const u8,
    info_hash: [sha1.digest_length]u8,
    info: struct {
        length: u32,
        name: []const u8,
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

const ClientAbbreviation: []const u8 = "MT";
const ClientVersion = "0001";

pub const Torrent = struct {
    allocator: std.mem.Allocator,

    peer_id: [20]u8,

    file_path: []const u8,
    raw_data: []const u8,

    metadata: Metadata,

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
        const tracker_url = dict.get("announce") orelse return error.InvalidTorrentFile;
        const created_by = dict.get("created by");
        const info = dict.get("info") orelse return error.InvalidTorrentFile;

        const info_hash = try calculateTokenHash(allocator, info);
        const info_dict = info.dictionary;

        const length = info_dict.get("length") orelse return error.InvalidTorrentFile;
        const name = info_dict.get("name") orelse return error.InvalidTorrentFile;
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
            .announce = tracker_url.string,
            .created_by = if (created_by) |cb| cb.string else null,
            .info_hash = info_hash,
            .info = .{
                .name = name.string,
                .length = @as(u32, @intCast(length.integer)),
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

    pub fn getPeers(self: @This()) !Peers {
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
    fn parsePeers(self: @This(), raw_response: std.ArrayList(u8)) !Peers {
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
    pub fn handshake(self: @This()) !net.Stream {
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

    /// Download a piece of the torrent.
    pub fn downloadPiece(self: @This(), piece_index: u32, output_file: []const u8) !void {
        // Open file. We do this first to ensure we can
        // write to the file before downloading the piece.
        const file = try std.fs.cwd().openFile(output_file, .{ .mode = .write_only });
        defer file.close();

        // Make a handshake with the peer.
        const stream = try self.handshake();

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

        std.debug.print("Download: Bitfield received\n", .{});

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

        std.debug.print("Download: Unchoke received\n", .{});

        // Calculate the piece's length.
        var piece_length = self.metadata.info.piece_length;
        if (piece_index == self.metadata.info.pieces.len - 1) {
            piece_length = @rem(self.metadata.info.length, self.metadata.info.piece_length);
        }

        const piece_buf = try self.allocator.alloc(u8, piece_length);
        defer self.allocator.free(piece_buf);

        // Download the full piece.
        try self.requestPieceBlocks(stream, piece_index, piece_buf, self.metadata.info.pieces[piece_index]);

        // Move cursor to the correct position in the file for the piece.
        const cursor_pos = piece_index * self.metadata.info.piece_length;
        try file.seekTo(cursor_pos);

        _ = try file.write(piece_buf);

        std.debug.print("Download: Piece {} downloaded, saved at {s}\n", .{ piece_index, output_file });
    }

    /// Request blocks of a piece from the peer, and verify the hash.
    fn requestPieceBlocks(self: @This(), stream: net.Stream, piece_index: u32, piece_buf: []u8, piece_hash: [sha1.digest_length]u8) !void {
        const writer = stream.writer().any();
        const reader = stream.reader().any();

        var begin: u32 = 0;
        const block_size = @min(16 * 1024, piece_buf.len);

        while (begin < piece_buf.len) : (begin += block_size) {
            // Send request for block.
            const cur_block_len = @min(block_size, piece_buf.len - begin);
            const request: PeerMessage = .{ .request = .{ .index = piece_index, .begin = begin, .length = cur_block_len } };
            try request.write(writer);

            // Receive the block.
            const response: PeerMessage = try PeerMessage.read(self.allocator, reader);
            defer response.deinit(self.allocator);
            if (response != .piece) {
                return error.UnexpectedMessageExpectedPiece;
            }

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
    }
};
