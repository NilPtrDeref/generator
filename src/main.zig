const std = @import("std");
const Allocator = std.mem.Allocator;

// Manipulated version of the standard lib `std.meta.ArgsTuple` function that removes the first argument from the resulting tuple
// so that the yielder interface isn't required of the user
pub fn ArgsTupleMinusFirst(comptime Function: type) type {
    const info = @typeInfo(Function);
    if (info != .@"fn")
        @compileError("ArgsTuple expects a function type");

    const function_info = info.@"fn";
    if (function_info.is_var_args)
        @compileError("Cannot create ArgsTuple for variadic function");

    var argument_field_list: [function_info.params.len - 1]type = undefined;
    inline for (function_info.params[1..], 0..) |arg, i| {
        const T = arg.type orelse @compileError("cannot create ArgsTuple for function with an 'anytype' parameter");
        argument_field_list[i] = T;
    }

    return CreateUniqueTuple(argument_field_list.len, argument_field_list);
}

// Copy of std.meta.CreateUniqueTuple that is required for modified ArgsTuple function to operate because standard library doesn't
// make it public
fn CreateUniqueTuple(comptime N: comptime_int, comptime types: [N]type) type {
    var tuple_fields: [types.len]std.builtin.Type.StructField = undefined;
    inline for (types, 0..) |T, i| {
        @setEvalBranchQuota(10_000);
        var num_buf: [128]u8 = undefined;
        tuple_fields[i] = .{
            .name = std.fmt.bufPrintZ(&num_buf, "{d}", .{i}) catch unreachable,
            .type = T,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(T),
        };
    }

    return @Type(.{
        .@"struct" = .{
            .is_tuple = true,
            .layout = .auto,
            .decls = &.{},
            .fields = &tuple_fields,
        },
    });
}

// Typed yielder interface that is used for caller to manage yielding back to the idled thread with a result value
pub fn Yielder(T: type) type {
    return struct {
        const Self = @This();

        const VTable = struct {
            yield: *const fn (*anyopaque, T) void,
        };

        ctx: *anyopaque,
        vtable: *const VTable,

        fn yield(self: Self, data: T) void {
            self.vtable.yield(self.ctx, data);
        }
    };
}

const Context = struct {
    rsp: u64 = 0,
    rbp: u64 = 0,
    rip: u64 = 0,
};

// Requires a function as well as its calling parameters and result type. It is the responsibility of the caller to manage non-stack memory within the generator.
pub fn Generator(f: anytype, args: ArgsTupleMinusFirst(@TypeOf(f)), T: type) type {
    // Enforce that parameter requirements are met of the caller
    comptime {
        const t = @typeInfo(@TypeOf(f));
        if (t != .@"fn")
            @compileError("f must be a function.");

        const info = t.@"fn";
        if (info.params.len < 1) {
            @compileError("Function must accept at least a yielder as it's first parameter.");
        }

        if (info.params[0].type.? != Yielder(T)) {
            var buffer: [1024]u8 = undefined;
            const fmt = std.fmt.bufPrint(@ptrCast(&buffer), "First argument must be a yield function the accepts the given return type.\nExpected: {any}\nGot: {any}", .{ Yielder, info.params[0].type.? }) catch unreachable;
            @compileError(fmt);
        }
    }

    return struct {
        const Self = @This();

        const State = enum {
            ready,
            running,
            finished,
        };

        // Manage stack pointers for the caller and the current generator
        current: Context,
        idle: Context,

        // Manage result value passing
        interface: Yielder(T),
        state: State,
        result: [@sizeOf(T)]u8,
        result_align: u32 = @alignOf(T),

        // Stack of the generator coroutine
        stack: []align(16) u8,
        args: ArgsTupleMinusFirst(@TypeOf(f)),

        pub fn init(gpa: Allocator) !*Self {
            var self = try gpa.create(Self);
            errdefer gpa.destroy(self);

            self.interface = .{
                .ctx = self,
                .vtable = &.{
                    .yield = Self.yield,
                },
            };
            self.state = .ready;
            self.args = args;
            self.stack = try gpa.alignedAlloc(u8, .@"16", 4096);
            @memset(self.stack, 0);
            errdefer gpa.free(self.stack);

            const TypeErased = struct {
                fn start() void {
                    // TODO: Replace with pulling current context pointer from struct and @fieldParentPtr instead of clobbering rbx
                    const s: *Self = asm volatile (
                        \\
                        : [ret] "={rbx}" (-> *Self),
                    );

                    @call(.auto, f, .{s.interface} ++ s.args);

                    // When the generator function returns, we should mark the Generator as finished and then switch back to the calling context
                    s.state = .finished;
                    Self.switch_context(&s.current, &s.idle);
                }
            };

            // Initialize stack
            // Prime the values that will be used if the function returns
            self.current.rsp = @intFromPtr(self.stack.ptr) + (self.stack.len - 8);
            @as(*u64, @ptrFromInt(self.current.rsp)).* = @intFromPtr(&TypeErased.start); // Set the function to be executed for generation
            self.current.rsp -= 8;

            self.current.rbp = self.current.rsp;
            self.current.rip = @intFromPtr(&TypeErased.start);

            return self;
        }

        pub fn yield(ctx: *anyopaque, data: T) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            @memcpy(&self.result, std.mem.asBytes(&data));
            Self.switch_context(&self.current, &self.idle);
        }

        pub fn next(self: *Self) ?T {
            const s = self;
            switch (self.state) {
                .ready => {
                    self.state = .running;
                    // TODO: Replace with pulling current context pointer from struct and @fieldParentPtr instead of clobbering rbx
                    asm volatile (
                        \\
                        :
                        : [self] "{rbx}" (s),
                    );
                    Self.switch_context(&s.idle, &s.current);
                },
                .running => {
                    Self.switch_context(&s.idle, &s.current);
                },
                .finished => {
                    return null;
                },
            }

            // Check after the ready or running state to make sure that the last call into the generator function didn't mark it as finished
            std.debug.print("Generator location: {*}\n", .{self});
            if (s.state == .finished) return null;

            var result: T = undefined;
            @memcpy(std.mem.asBytes(&result), &s.result);
            return result;
        }

        pub inline fn switch_context(from: *Context, to: *Context) void {
            asm volatile (
                \\ leaq 0f(%%rip), %%rdx
                \\ movq %%rsp, 0(%%rax)
                \\ movq %%rbp, 8(%%rax)
                \\ movq %%rdx, 16(%%rax)
                \\ movq 0(%%rcx), %%rsp
                \\ movq 8(%%rcx), %%rbp
                \\ jmpq *16(%%rcx)
                \\ 0:
                :
                : [from] "{rax}" (from),
                  [to] "{rcx}" (to),
            );
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.stack);
            gpa.destroy(self);
        }
    };
}

fn fib(y: Yielder(u64), max: u64) void {
    var first: u64 = 0;
    var second: u64 = 1;
    var next: u64 = 0;

    while (first <= max) {
        y.yield(first);
        next = first + second;
        first = second;
        second = next;
    }
}

// TODO: Convert main function to a test in preparation for deployment to github
pub fn main() !void {
    var gpa_impl = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_impl.deinit();
    const gpa = gpa_impl.allocator();

    // FIXME: Get non-comptime args working if possible.
    // var buffer: [64]u8 = undefined;
    // var r = std.fs.File.stdin().reader(&buffer);
    // const strnum = try r.interface.takeDelimiterExclusive('\n');
    // const trimnum = std.mem.trim(u8, strnum, "\n");
    // const num: u64 = try std.fmt.parseInt(u64, trimnum, 10);

    // FIXME: Generator returning one extra result. For some reason, the next function doesn't realize that the state is "finished" until we leave the function.
    // I'm probably clobbering the value of 'self' in the switch for ready state, it seems to be running the ready state every time.
    // Upon further investigation, this seems to be the case. The starting address in the next function is different than the ending address.
    // Need to look at how I can store the value on the stack and restore afterwards.
    // OR
    // Look into storing the ctx in the Context type as an anyopaque that the start function can access.
    var generator: *Generator(fib, .{4}, u64) = try .init(gpa);
    std.debug.print("Generator starting location: {*}\n", .{generator});
    while (generator.next()) |i| {
        std.debug.print("Generator state: {any}\n", .{generator.state});
        std.debug.print("Got result from generator: {d}\n", .{i});
    }

    // std.debug.assert(generator.next() == 1);
    // std.debug.assert(generator.next() == 1);
    // std.debug.assert(generator.next() == 2);
    // std.debug.assert(generator.next() == 3);
    // std.debug.assert(generator.next() == null);
    generator.deinit(gpa);
}
