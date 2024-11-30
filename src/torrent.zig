//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 30/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const bencode = @import("bencode.zig");
const utils = @import("utils.zig");

const TorrentMetadata = struct {
    announce: []const u8,
    info: struct {
        length: u64,
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

        const metadata = try metadataFromToken(object.root);

        return Torrent{
            .allocator = allocator,
            .file_path = file_path,
            .metadata = metadata,
        };
    }

    fn metadataFromToken(token: bencode.Token) !TorrentMetadata {
        const tracker_url: bencode.Token = token.dictionary.get("announce") orelse {
            return error.MissingAnnounceKey;
        };

        const info: bencode.Token = token.dictionary.get("info") orelse {
            return error.MissingInfoKey;
        };

        const length: bencode.Token = info.dictionary.get("length") orelse {
            return error.MissingLengthKey;
        };

        return TorrentMetadata{
            .announce = tracker_url.string,
            .info = .{ .length = @as(u64, @intCast(length.integer)) },
        };
    }
};
