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
        // pieces: [][]const u8,
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

    fn metadataFromToken(allocator: std.mem.Allocator, token: bencode.Token) !TorrentMetadata {
        const tracker_url: bencode.Token = token.dictionary.get("announce") orelse {
            return error.InvalidTorrentFile;
        };

        const created_by: ?bencode.Token = token.dictionary.get("created by");

        const info: bencode.Token = token.dictionary.get("info") orelse {
            return error.InvalidTorrentFile;
        };

        const info_hash = try calculateTokenHash(allocator, info);

        const length: bencode.Token = info.dictionary.get("length") orelse {
            return error.InvalidTorrentFile;
        };

        const name: bencode.Token = info.dictionary.get("name") orelse {
            return error.InvalidTorrentFile;
        };

        const piece_length: bencode.Token = info.dictionary.get("piece length") orelse {
            return error.InvalidTorrentFile;
        };

        return TorrentMetadata{
            .announce = tracker_url.string,
            .created_by = if (created_by) |cb| cb.string else null,
            .info_hash = info_hash,
            .info = .{ .length = @as(u64, @intCast(length.integer)), .name = name.string, .piece_length = @as(u64, @intCast(piece_length.integer)) },
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
