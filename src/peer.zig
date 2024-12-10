const std = @import("std");

const sha1 = std.crypto.hash.Sha1;

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
    fn handshake(self: @This()) !std.net.Stream {
        const address = std.net.Address.initIp4(self.ip, self.port);

        var stream = try std.net.tcpConnectToAddress(address);
        errdefer stream.close();

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
        std.debug.print("Handshake: Peer Id: {s}\n", .{std.fmt.bytesToHex(response_handshake.peer_id, .lower)});

        return stream;
    }

    /// Makes a handshake and sends initial requests to the peer.
    pub fn connect(self: @This()) !std.net.Stream {
        const peer_str = try self.toSlice(self.allocator);
        defer self.allocator.free(peer_str);

        std.debug.print("Connecting to peer: {s}\n", .{peer_str});

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

    pub fn disconnect(self: @This()) void {
        if (self.stream != null) {
            self.stream.?.close();
        }
    }

    /// Download a piece of the torrent.
    pub fn downloadPiece(self: @This(), stream: *std.net.Stream, torrent: *Torrent, piece_index: u32) ![]u8 {
        // Calculate the piece's length.
        var curr_piece_length = torrent.metadata.info.piece_length;
        if (piece_index == torrent.metadata.info.pieces.len - 1) {
            curr_piece_length = @rem(torrent.metadata.info.total_length, torrent.metadata.info.piece_length);
        }

        const piece_buf = try self.allocator.alloc(u8, curr_piece_length);
        errdefer self.allocator.free(piece_buf);

        // Download the full piece.
        try self.requestPieceBlocks(stream, piece_index, piece_buf, torrent.metadata.info.pieces[piece_index]);

        return piece_buf;
    }

    /// Request blocks of a piece from the peer, and verify the hash.
    fn requestPieceBlocks(self: @This(), stream: *std.net.Stream, piece_index: u32, piece_buf: []u8, piece_hash: [sha1.digest_length]u8) !void {
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

pub const Peers = std.ArrayList(Peer);
