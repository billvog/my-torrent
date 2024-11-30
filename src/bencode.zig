//
// This file is part of my-torrent, a BitTorrent client written in Zig.
//
// Created on 29/11/2024 by Vasilis Voyiadjis.
// Distributed under the MIT License.
//

const std = @import("std");
const stdout = std.io.getStdOut().writer();

const EncodingError = error{
    OutOfMemory,
    Overflow,
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
    dictionary: std.StringArrayHashMap(Token),
};

const DecodedToken = struct {
    value: Token,
    // The length of the *encoded* value.
    // Used to move the cursor during recursive decoding.
    length: usize,
};

pub const Object = struct {
    allocator: std.mem.Allocator,
    root: Token,

    pub fn init(allocator: std.mem.Allocator, root: Token) Object {
        return Object{ .allocator = allocator, .root = root };
    }

    pub fn initFromString(allocator: std.mem.Allocator, encoded_value: []const u8) !Object {
        const result = try decodeValue(allocator, encoded_value);
        return Object{ .allocator = allocator, .root = result.value };
    }

    pub fn deinit(self: @This()) void {
        deinitToken(self.allocator, &self.root);
    }

    pub fn encode(self: @This()) ![]const u8 {
        return encodeToken(self.allocator, self.root);
    }
};

pub fn encodeToken(allocator: std.mem.Allocator, token: Token) EncodingError![]const u8 {
    return switch (token) {
        .integer => try encodeInteger(allocator, token.integer),
        .string => try encodeString(allocator, token.string),
        .list => try encodeList(allocator, token.list),
        .dictionary => try encodeDictionary(allocator, token.dictionary),
    };
}

pub fn decodeValue(allocator: std.mem.Allocator, encoded_value: []const u8) TokenError!DecodedToken {
    const result = switch (encoded_value[0]) {
        '0'...'9' => try decodeString(encoded_value),
        'i' => try decodeNumber(encoded_value),
        'l' => try decodeList(allocator, encoded_value),
        'd' => try decodeDictionary(allocator, encoded_value),
        else => error.InvalidCharacter,
    };

    return result;
}

fn deinitToken(allocator: std.mem.Allocator, token: *const Token) void {
    switch (token.*) {
        .integer => {},
        .string => {},
        .list => {
            var list = token.list;
            for (list.items) |item| {
                deinitToken(allocator, &item);
            }
            list.deinit();
        },
        .dictionary => {
            var dict = token.dictionary;
            var it = dict.iterator();
            while (it.next()) |entry| {
                deinitToken(allocator, entry.value_ptr);
            }
            dict.deinit();
        },
    }
}

//
// Encoders
//

fn encodeInteger(allocator: std.mem.Allocator, value: i64) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try std.fmt.format(buffer.writer(), "i{d}e", .{value});

    return try buffer.toOwnedSlice();
}

fn encodeString(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try std.fmt.format(buffer.writer(), "{}:{s}", .{ value.len, value });

    return try buffer.toOwnedSlice();
}

fn encodeList(allocator: std.mem.Allocator, list: std.ArrayList(Token)) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try buffer.append('l');

    for (list.items) |item| {
        const encoded_item = try encodeToken(allocator, item);
        defer allocator.free(encoded_item);

        try buffer.appendSlice(encoded_item);
    }

    try buffer.append('e');

    return try buffer.toOwnedSlice();
}

fn encodeDictionary(allocator: std.mem.Allocator, dict: std.StringArrayHashMap(Token)) ![]const u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try buffer.append('d');

    var iterator = dict.iterator();
    while (iterator.next()) |entry| {
        const key = try encodeString(allocator, entry.key_ptr.*);
        defer allocator.free(key);

        const value = try encodeToken(allocator, entry.value_ptr.*);
        defer allocator.free(value);

        try buffer.appendSlice(key);
        try buffer.appendSlice(value);
    }

    try buffer.append('e');

    return try buffer.toOwnedSlice();
}

//
// Decoders
//

fn decodeNumber(encoded_value: []const u8) TokenError!DecodedToken {
    const end = std.mem.indexOf(u8, encoded_value, "e");
    if (end == null) {
        return error.InvalidArgument;
    }

    const number = try std.fmt.parseInt(i64, encoded_value[1..end.?], 10);

    return DecodedToken{ .value = Token{ .integer = number }, .length = end.? + 1 };
}

fn decodeString(encoded_value: []const u8) TokenError!DecodedToken {
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

    return DecodedToken{ .value = Token{ .string = string }, .length = end };
}

fn decodeList(allocator: std.mem.Allocator, encoded_value: []const u8) TokenError!DecodedToken {
    var list = std.ArrayList(Token).init(allocator);

    var index: usize = 1;

    while (index < encoded_value.len) {
        const token = try decodeValue(allocator, encoded_value[index..]);

        try list.append(token.value);

        index += token.length;
    }

    return DecodedToken{ .value = Token{ .list = list }, .length = index };
}

fn decodeDictionary(allocator: std.mem.Allocator, encoded_value: []const u8) TokenError!DecodedToken {
    var dict = std.StringArrayHashMap(Token).init(allocator);

    var index: usize = 1;

    while (encoded_value[index] != 'e' and index < encoded_value.len) {
        const key_token = try decodeValue(allocator, encoded_value[index..]);
        if (key_token.value != .string) {
            return error.InvalidDictionaryKey;
        }
        index += key_token.length;

        const value_token = try decodeValue(allocator, encoded_value[index..]);
        index += value_token.length;

        try dict.put(key_token.value.string, value_token.value);
    }

    return DecodedToken{ .value = Token{ .dictionary = dict }, .length = index };
}
