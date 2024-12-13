//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 12/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const sha1 = std.crypto.hash.Sha1;

const network = @import("network");
pub const Stream = network.Socket;

const Torrent = @import("torrent.zig").Torrent;

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

pub const Peers = std.ArrayList(Peer);

pub const Peer = struct {
    allocator: std.mem.Allocator,

    ip: [4]u8,
    port: u16,
    peer_id: ?[20]u8,

    torrent: *Torrent,

    pub fn toSlice(self: @This(), allocator: std.mem.Allocator) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}:{d}", .{ self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port });
    }

    /// Performs a handshake with the peer.
    fn handshake(self: @This()) !Stream {
        try network.init();
        defer network.deinit();

        const address = network.Address{ .ipv4 = .{ .value = self.ip } };

        var stream = try Stream.create(.ipv4, .tcp);
        errdefer stream.close();

        try stream.connect(.{ .address = address, .port = self.port });

        const writer = stream.writer();
        const reader = stream.reader();

        // Send the handshake message.
        try writer.writeStruct(Handshake{
            .info_hash = self.torrent.metadata.info_hash,
            .peer_id = self.torrent.peer_id,
        });

        // Receive the handshake response.
        const response_handshake = try reader.readStruct(Handshake);

        // Print peer's id.
        std.log.debug("Handshake: Peer Id: {s}", .{std.fmt.bytesToHex(response_handshake.peer_id, .lower)});

        return stream;
    }

    /// Makes a handshake and sends initial requests to the peer.
    pub fn connect(self: @This()) !Stream {
        const peer_str = try self.toSlice(self.allocator);
        defer self.allocator.free(peer_str);

        std.log.debug("Connecting to peer: {s}", .{peer_str});

        // Make a handshake with the peer.
        var stream = try self.handshake();
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

    pub fn keepAlive(_: @This(), stream: *Stream) !void {
        const writer = stream.writer().any();
        try writer.writeInt(u32, 0, .big);
    }

    /// Download a piece of the torrent.
    pub fn downloadPiece(self: @This(), stream: *Stream, piece_index: u32) ![]u8 {
        // Abbreviate the torrent metadata.
        const torrent_meta = self.torrent.metadata.info;

        // Calculate the piece's length.
        var curr_piece_length = torrent_meta.piece_length;
        if (piece_index == torrent_meta.pieces.len - 1) {
            curr_piece_length = @rem(torrent_meta.total_length, torrent_meta.piece_length);
        }

        const piece_buf = try self.allocator.alloc(u8, curr_piece_length);
        errdefer self.allocator.free(piece_buf);

        // Download the full piece.
        try self.requestPieceBlocks(stream, piece_index, piece_buf);

        return piece_buf;
    }

    /// Request blocks of a piece from the peer, and verify the hash.
    fn requestPieceBlocks(self: @This(), stream: *Stream, piece_index: u32, piece_buf: []u8) !void {
        const writer = stream.writer().any();
        const reader = stream.reader().any();

        var begin: u32 = 0;
        const block_size = @min(16 * 1024, piece_buf.len);

        std.log.debug("Downloading piece: {} -- block: {}", .{ piece_index, block_size });

        while (begin < piece_buf.len) : (begin += block_size) {
            // Send request for block.
            const cur_block_len = @min(block_size, piece_buf.len - begin);
            const request: PeerMessage = .{ .request = .{ .index = piece_index, .begin = begin, .length = cur_block_len } };
            try request.write(writer);

            std.log.debug("Requested block for piece: {} -- begin: {} -- length: {}", .{ piece_index, begin, cur_block_len });

            // Receive the block.
            const response: PeerMessage = try PeerMessage.read(self.allocator, reader);
            defer response.deinit(self.allocator);
            if (response != .piece) {
                return error.UnexpectedMessageExpectedPiece;
            }

            // Add leading space to align with 'requested block' log above.
            std.log.debug(" Received block for piece: {}", .{piece_index});

            // Verify it's the one we requested.
            if (begin != response.piece.begin or cur_block_len != response.piece.block.len) {
                return error.InvalidPieceBlock;
            }

            // Copy the block to the piece buffer.
            @memcpy(piece_buf[begin .. begin + cur_block_len], response.piece.block);
        }

        const piece_hash = self.torrent.metadata.info.pieces[piece_index];

        // Once the piece is downloaded, verify the hash.
        var hash: [sha1.digest_length]u8 = undefined;
        sha1.hash(piece_buf, &hash, .{});

        if (std.mem.eql(u8, &hash, &piece_hash) == false) {
            return error.InvalidPieceHash;
        }

        std.log.debug("Downloaded piece: {}", .{piece_index});
    }
};
