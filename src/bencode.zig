//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 29/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();

const TokenType = enum {
    Integer,
    String,
    List,
    Dictionary,
};

const TokenError = error{
    InvalidArgument,
    InvalidCharacter,
    InvalidDictionaryKey,
    OutOfMemory,
    Overflow,
};

pub const Token = union(enum) {
    integer: i64,
    string: []const u8,
    list: std.ArrayList(Token),
    dictionary: std.StringHashMap(Token),
};

const DecodedResult = struct {
    value: Token,
    length: usize,
};

pub fn decode(allocator: std.mem.Allocator, encoded_value: []const u8) !Token {
    const decoded_value = try internal_decode(allocator, encoded_value);
    if (decoded_value == null) {
        return error.InvalidArgument;
    }

    return decoded_value.?.value;
}

pub fn cleanup(allocator: std.mem.Allocator, token: *const Token) void {
    switch (token.*) {
        .integer => {},
        .string => {},
        .list => {
            var list = token.list;
            for (list.items) |item| {
                cleanup(allocator, &item);
            }
            list.deinit();
        },
        .dictionary => {
            var dict = token.dictionary;
            var it = dict.iterator();
            while (it.next()) |entry| {
                cleanup(allocator, entry.value_ptr);
            }
            dict.deinit();
        },
    }
}

pub fn tokenToString(allocator: std.mem.Allocator, token: Token) ![]const u8 {
    const result = switch (token) {
        .integer => {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();
            try std.fmt.format(buffer.writer(), "{}", .{token.integer});
            return try buffer.toOwnedSlice();
        },
        .string => {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();
            try std.fmt.format(buffer.writer(), "\"{s}\"", .{token.string});
            return try buffer.toOwnedSlice();
        },
        .list => {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();

            try buffer.append('[');

            for (token.list.items) |item| {
                const str = try tokenToString(allocator, item);

                try buffer.appendSlice(str);
                try buffer.append(',');
            }

            // Remove the trailing comma
            if (buffer.items.len > 1) {
                _ = buffer.pop();
            }

            try buffer.append(']');

            return try buffer.toOwnedSlice();
        },
        .dictionary => {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();

            try buffer.append('{');

            var iterator = token.dictionary.iterator();

            while (iterator.next()) |entry| {
                const value = try std.fmt.allocPrint(allocator, "\"{s}\": {s}", .{ entry.key_ptr.*, try tokenToString(allocator, entry.value_ptr.*) });
                defer allocator.free(value);

                try buffer.appendSlice(value);
                try buffer.append(',');
            }

            // Remove the trailing comma
            if (buffer.items.len > 1) {
                _ = buffer.pop();
            }

            try buffer.append('}');

            return try buffer.toOwnedSlice();
        },
    };

    return result;
}

pub fn errorToString(err: TokenError) []const u8 {
    return switch (err) {
        TokenError.InvalidArgument => "Invalid argument",
        TokenError.InvalidCharacter => "Invalid character",
        TokenError.InvalidDictionaryKey => "Invalid dictionary key. Dictionary keys must be strings",
        TokenError.OutOfMemory => "Out of memory",
        TokenError.Overflow => "Overflow",
    };
}

fn internal_decode(allocator: std.mem.Allocator, encoded_value: []const u8) TokenError!?DecodedResult {
    const result = switch (encoded_value[0]) {
        'e' => null,
        'i' => try decodeNumber(encoded_value),
        'l' => try decodeList(allocator, encoded_value),
        'd' => try decodeDictionary(allocator, encoded_value),
        else => try decodeString(encoded_value),
    };

    return result;
}

fn decodeNumber(encoded_value: []const u8) TokenError!DecodedResult {
    const end = std.mem.indexOf(u8, encoded_value, "e");
    if (end == null) {
        return error.InvalidArgument;
    }

    const number = try std.fmt.parseInt(i64, encoded_value[1..end.?], 10);

    return DecodedResult{ .value = Token{ .integer = number }, .length = end.? + 1 };
}

fn decodeList(allocator: std.mem.Allocator, encoded_value: []const u8) TokenError!DecodedResult {
    var list = std.ArrayList(Token).init(allocator);

    var index: usize = 1;

    while (index < encoded_value.len) {
        const token = try internal_decode(allocator, encoded_value[index..]);
        if (token == null) {
            break;
        }

        try list.append(token.?.value);

        index += token.?.length;
    }

    return DecodedResult{ .value = Token{ .list = list }, .length = index };
}

fn decodeString(encoded_value: []const u8) TokenError!DecodedResult {
    const separatorPos = std.mem.indexOf(u8, encoded_value, ":");
    if (separatorPos == null) {
        return error.InvalidArgument;
    }

    const length = try std.fmt.parseInt(usize, encoded_value[0..separatorPos.?], 10);
    if (length > encoded_value.len - separatorPos.?) {
        return error.InvalidArgument;
    }

    const start = separatorPos.? + 1;
    const end = start + length;

    const string = encoded_value[start..end];

    return DecodedResult{ .value = Token{ .string = string }, .length = end };
}

fn decodeDictionary(allocator: std.mem.Allocator, encoded_value: []const u8) TokenError!DecodedResult {
    var dict = std.StringHashMap(Token).init(allocator);

    var index: usize = 1;

    while (index < encoded_value.len) {
        const key_token = try internal_decode(allocator, encoded_value[index..]);
        if (key_token == null) {
            break;
        }

        if (key_token.?.value.string.len == 0) {
            return error.InvalidDictionaryKey;
        }

        index += key_token.?.length;

        const value_token = try internal_decode(allocator, encoded_value[index..]);
        if (value_token == null) {
            break;
        }

        index += value_token.?.length;

        try dict.put(key_token.?.value.string, value_token.?.value);
    }

    return DecodedResult{ .value = Token{ .dictionary = dict }, .length = index };
}
