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

const ClientAbbreviation: []const u8 = "MT";
const ClientVersion = "0001";

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

pub const Torrent = struct {
    allocator: std.mem.Allocator,

    peer_id: [20]u8,

    file_path: []const u8,
    raw_data: []const u8,

    metadata: Metadata,

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) !Torrent {
        // Read the .torrent file into a string.
        const raw_data = try utils.readFileIntoString(allocator, file_path);

        // Parse the bencoded data.
        var object: bencode.Object = bencode.Object.initFromString(allocator, raw_data) catch |err| {
            std.debug.print("Error: {}\n", .{err});
            return error.InvalidTorrentFile;
        };
        defer object.deinit();

        // Generate a peer ID.
        const peer_id = try generatePeerId(allocator);
        // Parse the metadata.
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
                .path = try allocator.dupe(u8, name.string),
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
};
