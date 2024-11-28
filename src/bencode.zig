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
    Integer: i64,
    String: []const u8,
    List: std.ArrayList(Token),
    Dictionary: std.StringHashMap(Token),
};

const DecodedResult = struct {
    value: Token,
    length: usize,
};

pub fn decode(alloc: std.mem.Allocator, encodedValue: []const u8) !Token {
    const decodedValue = try internal_decode(alloc, encodedValue);
    if (decodedValue == null) {
        return error.InvalidArgument;
    }

    return decodedValue.?.value;
}

pub fn cleanupToken(alloc: std.mem.Allocator, token: *const Token) void {
    switch (token.*) {
        .Integer => {},
        .String => {},
        .List => {
            var list = token.List;
            for (list.items) |item| {
                cleanupToken(alloc, &item);
            }
            list.deinit();
        },
        .Dictionary => {
            var dict = token.Dictionary;
            var it = dict.iterator();
            while (it.next()) |entry| {
                cleanupToken(alloc, entry.value_ptr);
            }
            dict.deinit();
        },
    }
}

pub fn tokenToString(alloc: std.mem.Allocator, token: Token) ![]const u8 {
    const result = switch (token) {
        .Integer => {
            var buffer = std.ArrayList(u8).init(alloc);
            defer buffer.deinit();
            try std.fmt.format(buffer.writer(), "{}", .{token.Integer});
            return try buffer.toOwnedSlice();
        },
        .String => {
            var buffer = std.ArrayList(u8).init(alloc);
            defer buffer.deinit();

            try buffer.append('"');
            try buffer.appendSlice(token.String);
            try buffer.append('"');

            return try buffer.toOwnedSlice();
        },
        .List => {
            var buffer = std.ArrayList(u8).init(alloc);
            defer buffer.deinit();

            try buffer.append('[');

            for (token.List.items) |item| {
                const str = try tokenToString(alloc, item);

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
        .Dictionary => {
            var buffer = std.ArrayList(u8).init(alloc);
            defer buffer.deinit();

            try buffer.append('{');

            var iterator = token.Dictionary.iterator();

            while (iterator.next()) |entry| {
                try buffer.append('"');
                try buffer.appendSlice(entry.key_ptr.*);
                try buffer.append('"');
                try buffer.append(':');
                try buffer.appendSlice(try tokenToString(alloc, entry.value_ptr.*));
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

fn internal_decode(alloc: std.mem.Allocator, encodedValue: []const u8) TokenError!?DecodedResult {
    const result = switch (encodedValue[0]) {
        'e' => null,
        'i' => try decodeNumber(encodedValue),
        'l' => try decodeList(alloc, encodedValue),
        'd' => try decodeDictionary(alloc, encodedValue),
        else => try decodeString(encodedValue),
    };

    return result;
}

fn decodeNumber(encodedValue: []const u8) TokenError!DecodedResult {
    const end = std.mem.indexOf(u8, encodedValue, "e");
    if (end == null) {
        return error.InvalidArgument;
    }

    const number = try std.fmt.parseInt(i64, encodedValue[1..end.?], 10);

    return DecodedResult{ .value = Token{ .Integer = number }, .length = end.? + 1 };
}

fn decodeList(alloc: std.mem.Allocator, encodedValue: []const u8) TokenError!DecodedResult {
    var list = std.ArrayList(Token).init(alloc);

    var index: usize = 1;

    while (index < encodedValue.len) {
        const token = try internal_decode(alloc, encodedValue[index..]);
        if (token == null) {
            break;
        }

        try list.append(token.?.value);

        index += token.?.length;
    }

    return DecodedResult{ .value = Token{ .List = list }, .length = index };
}

fn decodeString(encodedValue: []const u8) TokenError!DecodedResult {
    const separatorPos = std.mem.indexOf(u8, encodedValue, ":");
    if (separatorPos == null) {
        return error.InvalidArgument;
    }

    const length = try std.fmt.parseInt(usize, encodedValue[0..separatorPos.?], 10);
    if (length > encodedValue.len - separatorPos.?) {
        return error.InvalidArgument;
    }

    const start = separatorPos.? + 1;
    const end = start + length;

    const string = encodedValue[start..end];

    return DecodedResult{ .value = Token{ .String = string }, .length = end };
}

fn decodeDictionary(alloc: std.mem.Allocator, encodedValue: []const u8) TokenError!DecodedResult {
    var dict = std.StringHashMap(Token).init(alloc);

    var index: usize = 1;

    while (index < encodedValue.len) {
        const keyToken = try internal_decode(alloc, encodedValue[index..]);
        if (keyToken == null) {
            break;
        }

        if (keyToken.?.value.String.len == 0) {
            return error.InvalidDictionaryKey;
        }

        index += keyToken.?.length;

        const valueToken = try internal_decode(alloc, encodedValue[index..]);
        if (valueToken == null) {
            break;
        }

        index += valueToken.?.length;

        try dict.put(keyToken.?.value.String, valueToken.?.value);
    }

    return DecodedResult{ .value = Token{ .Dictionary = dict }, .length = index };
}
