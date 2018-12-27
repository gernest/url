const std = @import("std");
const Buffer = std.Buffer;
const warn = std.debug.warn;
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
    user: ?UserInfo,
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

    pub fn parse(a: *Allocator, raw_url: []const u8) !URL {
        const frag = split(raw_url, "#", true);
        var u = try parseInternal(a, raw_url, false);
        if (frag.y == null) {
            return u;
        }
        var buf = &try Buffer.init(a, "");
        defer buf.deinit();
        try unescape(buf, frag.y.?, encoding.path);
        u.fragment = buf.toOwnedSlice();
        return u;
    }

    fn parseInternal(a: *Allocator, raw_url: []const u8, via_request: bool) !URL {
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
            u.raw_query = s.y;
        }
        if (!hasPrefix(rest, "/")) {
            if (u.scheme != null) {
                u.opaque = rest;
                return u;
            }
            if (via_request) {
                return error.InvalidURL;
            }
            // Avoid confusion with malformed schemes, like cache_object:foo/bar.
            // See golang.org/issue/16822.
            //
            // RFC 3986, §3.3:
            // In addition, a URI reference (Section 4.1) may be a relative-path reference,
            // in which case the first path segment cannot contain a colon (":") character.
            const colon = mem.indexOf(u8, rest, ":");
            const slash = mem.indexOf(u8, rest, "/");
            if (colon != null and colon.? >= 0 and (slash == null or colon.? < slash.?)) {
                return error.BadURL;
            }
        }
        if ((u.scheme != null or !via_request) and !hasPrefix(rest, "///") and hasPrefix(rest, "//")) {
            const x = split(rest[2..], "/", false);
            if (x.y) |y| {
                rest = y;
            } else {
                rest = "";
            }
            const au = try parseAuthority(a, x.x);
            u.user = au.user;
            u.host = au.host;
        }
        if (rest.len > 0) {
            try setPath(a, &u, rest);
        }
        return u;
    }

    const Authority = struct {
        user: ?UserInfo,
        host: []const u8,
    };

    fn parseAuthority(allocator: *Allocator, authority: []const u8) !Authority {
        var buf = &try Buffer.init(allocator, "");
        defer buf.deinit();
        const idx = lastIndex(authority, "@");
        var res: Authority = undefined;
        if (idx == null) {
            res.host = try parseHost(allocator, authority);
        } else {
            res.host = try parseHost(allocator, authority[idx.? + 1 ..]);
        }
        if (idx == null) {
            res.user = null;
            return res;
        }

        const user_info = authority[0..idx.?];
        if (!validUserinfo(user_info)) {
            return error.InvalidUserInfo;
        }
        const s = split(user_info, ":", true);
        try unescape(buf, s.x, encoding.userPassword);
        const username = buf.toOwnedSlice();
        if (s.y) |y| {
            try buf.resize(0);
            try unescape(buf, y, encoding.userPassword);
            res.user = UserInfo.initWithPassword(username, buf.toOwnedSlice());
        } else {
            res.user = UserInfo.init(username);
        }
        return res;
    }

    fn parseHost(a: *Allocator, host: []const u8) ![]const u8 {
        var buf = &try Buffer.init(a, "");
        defer buf.deinit();
        if (hasPrefix(host, "[")) {
            // Parse an IP-Literal in RFC 3986 and RFC 6874.
            // E.g., "[fe80::1]", "[fe80::1%25en0]", "[fe80::1]:80".
            const idx = lastIndex(host, "]");
            if (idx == null) {
                // TODO: use result to improve error message
                return error.BadURL;
            }
            const i = idx.?;
            const colon_port = host[i + 1 ..];
            if (!validOptionalPort(colon_port)) {
                return error.BadURL;
            }
            // RFC 6874 defines that %25 (%-encoded percent) introduces
            // the zone identifier, and the zone identifier can use basically
            // any %-encoding it likes. That's different from the host, which
            // can only %-encode non-ASCII bytes.
            // We do impose some restrictions on the zone, to avoid stupidity
            // like newlines.
            if (index(host[0..i], "%25")) |zone| {
                try unescape(buf, host[0..zone], encoding.host);
                const host_1 = buf.toOwnedSlice();
                try unescape(buf, host[zone..i], encoding.zone);
                const host_2 = buf.toOwnedSlice();
                try unescape(buf, host[i..], encoding.host);
                const host_3 = buf.toOwnedSlice();
                var out_buf = &try Buffer.init(a, "");
                defer out_buf.deinit();
                try out_buf.append(host_1);
                try out_buf.append(host_2);
                try out_buf.append(host_3);
                return out_buf.toOwnedSlice();
            }
        }
        try unescape(buf, host, encoding.host);
        return buf.toOwnedSlice();
    }

    fn validOptionalPort(port: []const u8) bool {
        if (port.len == 0) {
            return true;
        }
        if (port[0] != ':') {
            return false;
        }
        for (port[1..]) |value| {
            if (value < '0' or value > '9') {
                return false;
            }
        }
        return true;
    }

    // validUserinfo reports whether s is a valid userinfo string per RFC 3986
    // Section 3.2.1:
    //     userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
    //     unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
    //     sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
    //                   / "*" / "+" / "," / ";" / "="
    //
    // It doesn't validate pct-encoded. The caller does that via func unescape.
    fn validUserinfo(s: []const u8) bool {
        for (s) |r| {
            if ('A' <= r and r <= 'Z') {
                continue;
            }
            if ('a' <= r and r <= 'z') {
                continue;
            }
            if ('0' <= r and r <= '9') {
                continue;
            }
            switch (r) {
                '-', '.', '_', ':', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', '%', '@' => {},
                else => {
                    return false;
                },
            }
        }
        return true;
    }
};

fn setPath(a: *Allocator, u: *URL, path: []const u8) !void {
    var buf = &try Buffer.init(a, "");
    defer buf.deinit();
    try unescape(buf, path, encoding.path);
    u.path = buf.toOwnedSlice();
    try buf.resize(0);
    try escape(buf, u.path.?, encoding.path);
    if (!buf.eql(path)) {
        u.raw_path = path;
    }
}

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
        } else {
            return x;
        }
    }
    return x;
}

fn lastIndex(s: []const u8, sub: []const u8) ?usize {
    return mem.lastIndexOf(u8, s, sub);
}

fn index(s: []const u8, sub: []const u8) ?usize {
    return mem.indexOf(u8, s, sub);
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

// result returns a wrapper struct that helps improve error handling. Panicking
// in production is bad, and adding more context to errors improves the
// experience especially with parsing.
fn result(comptime Value: type, ResultError: type) type {
    return struct {
        const Self = @This();
        value: Result,
        message: ?[]const u8,
        pub const Error = ResultError;

        pub fn withErr(e: Error, msg: ?[]const u8) Self {
            return Self{
                .value = Result{ .err = e },
                .message = msg,
            };
        }

        pub fn withValue(e: Error) Self {
            return Self{
                .value = Result{ .value = e },
                .message = null,
            };
        }

        pub const Result = union(enum) {
            err: Error,
            value: Value,
        };

        pub fn unwrap(self: Self) Error!Value {
            return switch (self.value) {
                Error => |err| err,
                Value => |v| v,
                else => unreachable,
            };
        }
    };
}
