const url = @import("./url.zig");
const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const debug = std.debug;

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

test "URL" {
    var u = url.URL.init(debug.global_allocator);
    defer u.deinit();
}
