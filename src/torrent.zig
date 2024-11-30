//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 30/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const sha1 = std.crypto.hash.Sha1;

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

pub const Torrent = struct {
    allocator: std.mem.Allocator,
    file_path: []const u8,

    metadata: TorrentMetadata,

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !Torrent {
        const file_contents = try utils.readFileIntoString(allocator, file_path);

        var object = bencode.Object.initFromString(allocator, file_contents) catch {
            return error.InvalidTorrentFile;
        };
        defer object.deinit();

        const metadata = try metadataFromToken(allocator, object.root);

        return Torrent{
            .allocator = allocator,
            .file_path = file_path,
            .metadata = metadata,
        };
    }

    pub fn deinit(self: @This()) void {
        self.metadata.info.pieces.deinit();
    }

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
};
