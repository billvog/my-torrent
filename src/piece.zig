//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 12/12/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");

const Torrent = @import("torrent.zig").Torrent;

const FileSpan = struct {
    file_index: usize,
    piece_offset: u32,
    file_offset: u32,
    length: u32,
};

pub fn getPieceFileSpans(allocator: std.mem.Allocator, torrent: *const Torrent, piece_index: u32) ![]FileSpan {
    var spans = std.ArrayList(FileSpan).init(allocator);

    const piece_size = torrent.metadata.info.piece_length;
    const piece_offset = @as(u32, piece_index * piece_size);

    var current_offset: u32 = 0;
    var remaining = piece_size;

    // Iterate through files to find which ones this piece intersects
    for (torrent.metadata.info.files.items, 0..) |file, i| {
        if (current_offset + file.length <= piece_offset) {
            // This file ends before our piece starts
            current_offset += file.length;
            continue;
        }

        if (current_offset >= piece_offset + piece_size) {
            // This file starts after our piece ends
            break;
        }

        // Calculate overlap
        const file_start = if (current_offset < piece_offset)
            piece_offset - current_offset
        else
            0;

        const available = @as(u32, file.length - file_start);
        const span_length = @as(u32, @min(remaining, available));

        try spans.append(.{
            .file_index = i,
            .piece_offset = if (current_offset >= piece_offset)
                current_offset - piece_offset
            else
                0,
            .file_offset = file_start,
            .length = span_length,
        });

        remaining -= span_length;
        if (remaining == 0) break;

        current_offset += file.length;
    }

    return spans.toOwnedSlice();
}
