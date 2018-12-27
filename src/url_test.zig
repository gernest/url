const url = @import("./url.zig");
const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const warn = std.debug.warn;
const debug = std.debug;
const UserInfo = url.UserInfo;
const URL = url.URL;
const EscapeTest = struct {
    in: []const u8,
    out: []const u8,
    err: ?url.Error,
};

fn unescapePassingTests() []const EscapeTest {
    const ts = []EscapeTest{
        EscapeTest{
            .in = "",
            .out = "",
            .err = null,
        },
        EscapeTest{
            .in = "1%41",
            .out = "1A",
            .err = null,
        },
        EscapeTest{
            .in = "1%41%42%43",
            .out = "1ABC",
            .err = null,
        },
        EscapeTest{
            .in = "%4a",
            .out = "J",
            .err = null,
        },
        EscapeTest{
            .in = "%6F",
            .out = "o",
            .err = null,
        },
        EscapeTest{
            .in = "a+b",
            .out = "a b",
            .err = null,
        },
        EscapeTest{
            .in = "a%20b",
            .out = "a b",
            .err = null,
        },
    };
    return ts[0..];
}

fn unescapeFailingTests() []const EscapeTest {
    const ts = []EscapeTest{
        EscapeTest{
            .in = "%",
            .out = "",
            .err = url.Error.EscapeError,
        },
        EscapeTest{
            .in = "%a",
            .out = "",
            .err = url.Error.EscapeError,
        },
        EscapeTest{
            .in = "%1",
            .out = "",
            .err = url.Error.EscapeError,
        },
        EscapeTest{
            .in = "123%45%6",
            .out = "",
            .err = url.Error.EscapeError,
        },
        EscapeTest{
            .in = "%zzzzz",
            .out = "",
            .err = url.Error.EscapeError,
        },
    };
    return ts[0..];
}

test "QueryUnEscape" {
    var buffer = try std.Buffer.init(debug.global_allocator, "");
    var buf = &buffer;
    defer buf.deinit();
    for (unescapePassingTests()) |ts| {
        try url.queryUnEscape(buf, ts.in);
        assert(buf.eql(ts.out));
        buf.shrink(0);
    }
    for (unescapeFailingTests()) |ts| {
        if (url.queryUnEscape(buf, ts.in)) {
            @panic("expected an error");
        } else |err| {
            assert(err == ts.err.?);
        }
        buf.shrink(0);
    }
}

fn queryEscapeTests() []const EscapeTest {
    const ts = []EscapeTest{
        EscapeTest{
            .in = "",
            .out = "",
            .err = null,
        },
        EscapeTest{
            .in = "abc",
            .out = "abc",
            .err = null,
        },
        EscapeTest{
            .in = "one two",
            .out = "one+two",
            .err = null,
        },
        EscapeTest{
            .in = "10%",
            .out = "10%25",
            .err = null,
        },
        EscapeTest{
            .in = " ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;",
            .out = "+%3F%26%3D%23%2B%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09%3A%2F%40%24%27%28%29%2A%2C%3B",
            .err = null,
        },
    };
    return ts[0..];
}

test "QueryEscape" {
    var buffer = try std.Buffer.init(debug.global_allocator, "");
    var buf = &buffer;
    defer buf.deinit();
    for (queryEscapeTests()) |ts| {
        try url.queryEscape(buf, ts.in);
        assert(buf.eql(ts.out));
        buf.shrink(0);
    }
}

fn pathEscapeTests() []const EscapeTest {
    const ts = []EscapeTest{
        EscapeTest{
            .in = "",
            .out = "",
            .err = null,
        },
        EscapeTest{
            .in = "abc",
            .out = "abc",
            .err = null,
        },
        EscapeTest{
            .in = "abc+def",
            .out = "abc+def",
            .err = null,
        },
        EscapeTest{
            .in = "one two",
            .out = "one%20two",
            .err = null,
        },
        EscapeTest{
            .in = "10%",
            .out = "10%25",
            .err = null,
        },
        EscapeTest{
            .in = " ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;",
            .out = "%20%3F&=%23+%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09:%2F@$%27%28%29%2A%2C%3B",
            .err = null,
        },
    };
    return ts[0..];
}

test "PathEscape" {
    var buffer = try std.Buffer.init(debug.global_allocator, "");
    var buf = &buffer;
    defer buf.deinit();
    for (pathEscapeTests()) |ts| {
        try url.pathEscape(buf, ts.in);
        assert(buf.eql(ts.out));
        buf.shrink(0);
    }
}

const TestURL = struct {
    scheme: ?[]const u8,
    opaque: ?[]const u8,
    user: ?UserInfo,
    host: ?[]const u8,
    path: ?[]const u8,
    raw_path: ?[]const u8,
    force_query: ?bool,
    raw_query: ?[]const u8,
    fragment: ?[]const u8,

    fn init(
        scheme: ?[]const u8,
        opaque: ?[]const u8,
        user: ?UserInfo,
        host: ?[]const u8,
        path: ?[]const u8,
        raw_path: ?[]const u8,
        force_query: ?bool,
        raw_query: ?[]const u8,
        fragment: ?[]const u8,
    ) TestURL {
        return TestURL{
            .scheme = scheme,
            .opaque = opaque,
            .user = user,
            .host = host,
            .path = path,
            .raw_path = raw_path,
            .force_query = force_query,
            .raw_query = raw_query,
            .fragment = fragment,
        };
    }
};

const URLTest = struct {
    in: []const u8,
    out: TestURL,
    round_trip: ?[]const u8,

    fn init(
        in: []const u8,
        out: TestURL,
        round_trip: ?[]const u8,
    ) URLTest {
        return URLTest{
            .in = in,
            .out = out,
            .round_trip = round_trip,
        };
    }
};

const url_tests = []URLTest{
    // no path
    URLTest.init("http://www.google.com", TestURL.init("http", null, null, "www.google.com", null, null, null, null, null), ""),
    // path
    URLTest.init("http://www.google.com/", TestURL.init("http", null, null, "www.google.com", "/", null, null, null, null), ""),
    // path with hex escaping
    URLTest.init("http://www.google.com/file%20one%26two", TestURL.init("http", null, null, "www.google.com", "/file one&two", "/file%20one%26two", null, null, null), ""),
    // user
    URLTest.init("ftp://webmaster@www.google.com/", TestURL.init("ftp", null, UserInfo.init("webmaster"), "www.google.com", "/", null, null, null, null), ""),
    // escape sequence in username
    URLTest.init("ftp://john%20doe@www.google.com/", TestURL.init("ftp", null, UserInfo.init("john doe"), "www.google.com", "/", null, null, null, null), "ftp://john%20doe@www.google.com/"),
    // empty query
    URLTest.init("http://www.google.com/?", TestURL.init("http", null, null, "www.google.com", "/", null, true, null, null), ""),
    // query ending in question mark (Issue 14573)
    URLTest.init("http://www.google.com/?foo=bar?", TestURL.init("http", null, null, "www.google.com", "/", null, null, "foo=bar?", null), ""),
    // query
    URLTest.init("http://www.google.com/?q=go+language", TestURL.init("http", null, null, "www.google.com", "/", null, null, "q=go+language", null), ""),
    // query with hex escaping: NOT parsed
    URLTest.init("http://www.google.com/?q=go%20language", TestURL.init("http", null, null, "www.google.com", "/", null, null, "q=go%20language", null), ""),
    // %20 outside query
    URLTest.init("http://www.google.com/a%20b?q=c+d", TestURL.init("http", null, null, "www.google.com", "/a b", null, null, "q=c+d", null), ""),
    // path without leading /, so no parsing
    URLTest.init("http:www.google.com/?q=go+language", TestURL.init("http", "www.google.com/", null, null, null, null, null, "q=go+language", null), "http:www.google.com/?q=go+language"),
    // path without leading /, so no parsing
    URLTest.init("http:%2f%2fwww.google.com/?q=go+language", TestURL.init("http", "%2f%2fwww.google.com/", null, null, null, null, null, "q=go+language", null), "http:%2f%2fwww.google.com/?q=go+language"),
    // non-authority with path
    URLTest.init("mailto:/webmaster@golang.org", TestURL.init("mailto", null, null, null, "/webmaster@golang.org", null, null, null, null), "mailto:///webmaster@golang.org"),
    // non-authority
    URLTest.init("mailto:webmaster@golang.org", TestURL.init("mailto", "webmaster@golang.org", null, null, null, null, null, null, null), ""),
    // unescaped :// in query should not create a scheme
    URLTest.init("/foo?query=http://bad", TestURL.init(null, null, null, null, "/foo", null, null, "query=http://bad", null), ""),
    // leading // without scheme should create an authority
    URLTest.init("//foo", TestURL.init(null, null, null, "foo", null, null, null, null, null), ""),
    // leading // without scheme, with userinfo, path, and query
    URLTest.init("//user@foo/path?a=b", TestURL.init(null, null, UserInfo.init("user"), "foo", "/path", null, null, "a=b", null), ""),
    // Three leading slashes isn't an authority, but doesn't return an error.
    // (We can't return an error, as this code is also used via
    // ServeHTTP -> ReadRequest -> Parse, which is arguably a
    // different URL parsing context, but currently shares the
    // same codepath)
    URLTest.init("///threeslashes", TestURL.init(null, null, null, null, "///threeslashes", null, null, null, null), ""),
    URLTest.init("http://user:password@google.com", TestURL.init("http", null, UserInfo.initWithPassword("user", "password"), "google.com", null, null, null, null, null), "http://user:password@google.com"),
};

test "URL.parse" {
    var allocator = std.debug.global_allocator;
    for (url_tests) |ts| {
        var a = std.heap.ArenaAllocator.init(allocator);
        errdefer a.deinit();
        const u = try URL.parse(&a.allocator, ts.in);
        warn("{}\n", u);
        a.deinit();
    }
}
