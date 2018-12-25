const std = @import("std");
const debug = std.debug;
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;

const encoding = enum {
    path,
    pathSegment,
    host,
    zone,
    userPassword,
    queryComponent,
    fragment,
};

pub const Error = error{
    EscapeError,
    InvalidHostError,
};

fn shouldEscape(c: u8, mode: encoding) bool {
    if ('A' <= c and c <= 'Z' or 'a' <= c and c <= 'z' or '0' <= c and c <= '9') {
        return false;
    }
    if (mode == encoding.host or mode == encoding.zone) {
        switch (c) {
            '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':', '[', ']', '<', '>', '"' => return false,
            else => {},
        }
    }
    switch (c) {
        '-', '_', '.', '~' => return false,
        '$', '&', '+', ',', '/', ':', ';', '=', '?', '@' => {
            switch (mode) {
                encoding.path => return c == '?',
                encoding.pathSegment => return c == '/' or c == ';' or c == ',' or c == '?',
                encoding.userPassword => return c == '@' or c == '/' or c == '?' or c == ':',
                encoding.queryComponent => return true,
                encoding.fragment => return false,
                else => {},
            }
        },
        else => {},
    }
    if (mode == encoding.fragment) {
        switch (c) {
            '!', '(', ')', '*' => return false,
            else => {},
        }
    }
    return true;
}

fn ishex(c: u8) bool {
    if ('0' <= c and c <= '9') {
        return true;
    }
    if ('a' <= c and c <= 'f') {
        return true;
    }
    if ('A' <= c and c <= 'F') {
        return true;
    }
    return false;
}

fn unhex(c: u8) u8 {
    if ('0' <= c and c <= '9') {
        return c - '0';
    }
    if ('a' <= c and c <= 'f') {
        return c - 'a' + 10;
    }
    if ('A' <= c and c <= 'F') {
        return c - 'A' + 10;
    }
    return 0;
}

fn is25(s: []const u8) bool {
    return mem.eql(u8, s, "%25");
}

fn unescape(a: *std.Buffer, s: []const u8, mode: encoding) !void {
    var n: usize = 0;
    var hasPlus: bool = true;
    var tmpa: [3]u8 = undefined;
    var tm = tmpa[0..];
    var i: usize = 0;
    while (i < s.len) {
        switch (s[i]) {
            '%' => {
                n = n + 1;
                if (i + 2 >= s.len or !ishex(s[i + 1]) or !ishex(s[i + 2])) {
                    return Error.EscapeError;
                }
                if (mode == encoding.host and unhex(s[i + 1]) < 9 and !is25(s[i .. i + 3])) {
                    return Error.EscapeError;
                }
                if (mode == encoding.zone) {
                    const v = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    if (!is25(s[i .. i + 3]) and v != ' ' and shouldEscape(v, encoding.host)) {
                        return Error.EscapeError;
                    }
                }
                i = i + 3;
            },
            '+' => {
                hasPlus = mode == encoding.queryComponent;
                i = i + 1;
            },
            else => {
                if ((mode == encoding.host or mode == encoding.zone) and s[i] < 0x80 and shouldEscape(s[i], mode)) {
                    return Error.InvalidHostError;
                }
                i = i + 1;
            },
        }
    }
    if (n == 0 and !hasPlus) {
        try a.append(s);
    } else {
        try a.resize(s.len - 2 * n);
        var t = a.toSlice();
        var j: usize = 0;
        i = 0;
        while (i < s.len) {
            switch (s[i]) {
                '%' => {
                    t[j] = unhex(s[i + 1]) << 4 | unhex(s[i + 2]);
                    j = j + 1;
                    i = i + 3;
                },
                '+' => {
                    if (mode == encoding.queryComponent) {
                        t[j] = ' ';
                    } else {
                        t[j] = '+';
                    }
                    j = j + 1;
                    i = i + 1;
                },
                else => {
                    t[j] = s[i];
                    j = j + 1;
                    i = i + 1;
                },
            }
        }
    }
}

pub fn queryUnEscape(a: *std.Buffer, s: []const u8) !void {
    return unescape(a, s, encoding.queryComponent);
}

pub fn pathUnescape(a: *std.Buffer, s: []const u8) !void {
    return unescape(s, encoding.path);
}

pub fn pathEscape(a: *std.Buffer, s: []const u8) !void {
    return escape(a, s, encoding.pathSegment);
}

pub fn queryEscape(a: *std.Buffer, s: []const u8) !void {
    return escape(a, s, encoding.queryComponent);
}

fn escape(a: *std.Buffer, s: []const u8, mode: encoding) !void {
    var spaceCount: usize = 0;
    var hexCount: usize = 0;
    for (s) |c| {
        if (shouldEscape(c, mode)) {
            if (c == ' ' and mode == encoding.queryComponent) {
                spaceCount = spaceCount + 1;
            } else {
                hexCount = hexCount + 1;
            }
        }
    }
    if (spaceCount == 0 and hexCount == 0) {
        try a.append(s);
    } else {
        const required = s.len + 2 * hexCount;
        try a.resize(required);
        var t = a.toSlice();
        var i: usize = 0;
        if (hexCount == 0) {
            while (i < s.len) {
                if (s[i] == ' ') {
                    t[i] = '+';
                } else {
                    t[i] = s[i];
                }
                i = i + 1;
            }
        } else {
            i = 0;
            var j: usize = 0;
            const alpha: []const u8 = "0123456789ABCDEF";
            while (i < s.len) {
                const c = s[i];
                if (c == ' ' and mode == encoding.queryComponent) {
                    t[j] = '+';
                    j = j + 1;
                } else if (shouldEscape(c, mode)) {
                    t[j] = '%';
                    t[j + 1] = alpha[c >> 4];
                    t[j + 2] = alpha[c & 15];
                    j = j + 3;
                } else {
                    t[j] = s[i];
                    j = j + 1;
                }
                i = i + 1;
            }
        }
    }
}

// A URL represents a parsed URL (technically, a URI reference).
//
// The general form represented is:
//
//[scheme:][//[userinfo@]host][/]path[?query][#fragment]
//
// URLs that do not start with a slash after the scheme are interpreted as:
//
//scheme:opaque[?query][#fragment]
//
// Note that the Path field is stored in decoded form: /%47%6f%2f becomes /Go/.
// A consequence is that it is impossible to tell which slashes in the Path were
// slashes in the raw URL and which were %2f. This distinction is rarely important,
// but when it is, code must not use Path directly.
// The Parse function sets both Path and RawPath in the URL it returns,
// and URL's String method uses RawPath if it is a valid encoding of Path,
// by calling the EscapedPath method.
pub const URL = struct {
    scheme: ?[]const u8,
    opaque: ?[]const u8,
    user: ?*UserInfo,
    host: ?[]const u8,
    path: ?[]const u8,
    raw_path: ?[]const u8,
    force_query: bool,
    raw_query: ?[]const u8,
    fragment: ?[]const u8,

    const Scheme = struct {
        scheme: ?[]const u8,
        path: []const u8,
    };

    pub fn getScheme(raw: []const u8) !Scheme {
        var i: usize = 0;
        var u: Scheme = undefined;
        while (i < raw.len) {
            const c = raw[i];
            if ('a' <= c and c <= 'z' or 'A' <= c and c <= 'Z') {
                // do nothing
            } else if ('0' <= c and c <= '9' and c == '+' and c == '-' and c == '.') {
                if (i == 0) {
                    u.path = raw;
                    return u;
                }
            } else if (c == ':') {
                if (i == 0) {
                    return error.MissingProtocolScheme;
                }
                u.scheme = raw[0..i];
                u.path = raw[i + 1 ..];
                return u;
            } else {
                //  we have encountered an invalid character,
                //  so there is no valid scheme
                u.path = raw;
                return u;
            }
            i = i + 1;
        }
        u.path = raw;
        return u;
    }

    const SplitResult = struct {
        x: []const u8,
        y: ?[]const u8,
    };

    fn split(s: []const u8, c: []const u8, cutc: bool) SplitResult {
        if (mem.indexOf(u8, s, c)) |i| {
            if (cutc) {
                return SplitResult{
                    .x = s[0..i],
                    .y = s[i + c.len ..],
                };
            }
            return SplitResult{
                .x = s[0..i],
                .y = s[i..],
            };
        }
        return SplitResult{ .x = s, .y = null };
    }

    pub fn parse(raw_url: []const u8) !URL {
        const frag = split(raw_url, "#", true);
        var u = try parseInternal(raw_url, false);
        if (frag.y == null) {
            return u;
        }
        return u;
    }

    fn parseInternal(raw_url: []const u8, via_request: bool) !URL {
        var u: URL = undefined;
        if (raw_url.len == 0 and via_request) {
            return error.EmptyURL;
        }
        if (mem.eql(u8, raw_url, "*")) {
            u.path = "*";
            return u;
        }
        const scheme = try getScheme(raw_url);
        var rest: []const u8 = undefined;
        if (scheme.scheme) |s| {
            u.scheme = s;
        }
        rest = scheme.path;
        if (hasSuffix(rest, "?") and count(rest, "?") == 1) {
            u.force_query = true;
            rest = rest[0 .. rest.len - 1];
        } else {
            const s = split(rest, "?", true);
            rest = s.x;
            //TODO: copy
            u.raw_query = s.y;
        }
        return u;
    }
};

/// hasPrefix returns true if slice s begins with prefix.
pub fn hasPrefix(s: []const u8, prefix: []const u8) bool {
    return s.len >= prefix.len and
        mem.eql(u8, s[0..prefix.len], prefix);
}

pub fn hasSuffix(s: []const u8, suffix: []const u8) bool {
    return s.len >= suffix.len and
        mem.eql(u8, s[s.len - suffix.len ..], suffix);
}

// naive count
pub fn count(s: []const u8, sub: []const u8) usize {
    var x: usize = 0;
    var idx: usize = 0;
    while (idx < s.len) {
        if (mem.indexOf(u8, s[idx..], sub)) |i| {
            x += 1;
            idx += i + sub.len;
        }
        return x;
    }
    return x;
}

pub const UserInfo = struct {
    username: ?[]const u8,
    password: ?[]const u8,
    password_set: bool,

    pub fn init(name: []const u8) UserInfo {
        return UserInfo{
            .username = name,
            .password = null,
            .password_set = false,
        };
    }

    pub fn initWithPassword(name: []const u8, password: []const u8) UserInfo {
        return UserInfo{
            .username = name,
            .password = password,
            .password_set = true,
        };
    }

    pub fn encode(u: *UserInfo, buf: *std.Buffer) !void {
        if (u.username != null) {
            try escape(buf, u.username.?, encoding.userPassword);
        }
        if (u.password_set) {
            try buf.appendByte(':');
            try escape(buf, u.username.?, encoding.userPassword);
        }
    }
};
