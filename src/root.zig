const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const page_size = std.heap.page_size_min;
pub const stack_alignment = 16;
pub const StackInfo = struct {
    ptr: [*]align(page_size) u8,
    len: usize,
    top: usize,
    valgrind_stack_id: usize = 0,

    pub fn init(info: *StackInfo, size: usize) !void {
        // Ensure that the stack is at least two pages long so that we can have a guard page.
        const adjusted = try std.math.ceilPowerOfTwo(usize, @max(size, 2 * page_size));

        const allocation = try posix.mmap(
            null,
            adjusted,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .STACK = true },
            -1,
            0,
        );
        errdefer posix.munmap(allocation);
        _ = posix.madvise(allocation.ptr, allocation.len, posix.MADV.NOHUGEPAGE) catch {};

        // Add guard page.
        try posix.mprotect(allocation[0..page_size], posix.PROT.NONE);

        info.* = .{
            .ptr = allocation.ptr,
            .len = allocation.len,
            .top = @intFromPtr(allocation.ptr) + adjusted,
        };

        if (builtin.mode == .Debug and builtin.valgrind_support) {
            info.valgrind_stack_id = std.valgrind.stackRegister(allocation[page_size..]);
        }
    }

    pub fn deinit(info: *StackInfo) void {
        if (builtin.mode == .Debug and builtin.valgrind_support) {
            if (info.valgrind_stack_id != 0) {
                std.valgrind.stackDeregister(info.valgrind_stack_id);
            }
        }

        const allocation: []align(page_size) u8 = info.ptr[0..info.len];
        posix.munmap(allocation);
    }
};

// Typed yielder interface that is used for caller to manage yielding back to the idled thread with a result value
pub fn Yielder(T: type) type {
    return struct {
        const Self = @This();

        const VTable = struct {
            yield: *const fn (*anyopaque, T) void,
        };

        ctx: *anyopaque,
        vtable: *const VTable,

        pub fn yield(self: Self, data: T) void {
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
pub fn Generator(f: anytype, T: type) type {
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

    const FullArgs = std.meta.ArgsTuple(@TypeOf(f));
    const args_fields = std.meta.fields(FullArgs);
    comptime var user_types: [args_fields.len - 1]type = undefined;
    inline for (args_fields[1..], 0..) |field, i| {
        user_types[i] = field.type;
    }
    const Args = std.meta.Tuple(&user_types);

    return struct {
        const Self = @This();

        const State = enum {
            ready,
            running,
            finished,
        };

        // Manage stack pointers for the caller and the current generator
        // current belongs to the generator
        current: Context,
        // idle belongs to the owner of the generator
        idle: Context,

        // Manage result value passing
        interface: Yielder(T),
        state: State,
        args: Args,
        result: [@sizeOf(T)]u8,
        result_align: u32 = @alignOf(T),

        // Stack of the generator coroutine
        stack: StackInfo,

        pub fn init(gpa: Allocator, args: Args) !*Self {
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

            // Default the stack size to a max of 8MiB
            // TODO: Take in the stack size as a configurable option
            try self.stack.init(8 * 1024 * 1024);
            errdefer self.stack.deinit();

            // Initialize stack
            // Prime the values that will be used if the function returns
            self.current.rbp = 0;
            self.current.rsp = self.stack.top;
            self.current.rip = @intFromPtr(&entrypoint);

            return self;
        }

        // Must have an entrypoint function that adds an address to the stack so that the start method call doesn't misalign the stack
        fn entrypoint() callconv(.naked) noreturn {
            asm volatile (
                \\ leaq 1f(%%rip), %%rax
                \\ pushq %%rax
                \\ jmpq *%[f]
                \\1:
                :
                : [f] "{rdx}" (&start),
            );
        }

        fn start() callconv(.c) noreturn {
            const current: *Context = asm volatile (
                \\
                : [ret] "={rcx}" (-> *Context),
            );
            const s: *Self = @fieldParentPtr("current", current);

            s.state = .running;
            @call(.auto, f, .{s.interface} ++ s.args);

            // When the generator function returns, we should mark the Generator as finished and then switch back to the calling context
            s.state = .finished;
            Self.switch_context(&s.current, &s.idle);

            unreachable;
        }

        fn yield(ctx: *anyopaque, data: T) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            @memcpy(&self.result, std.mem.asBytes(&data));
            Self.switch_context(&self.current, &self.idle);
        }

        pub fn next(self: *Self) ?T {
            switch (self.state) {
                .ready, .running => {
                    Self.switch_context(&self.idle, &self.current);
                },
                .finished => {
                    return null;
                },
            }

            // Check after the ready or running state to make sure that the last call into the generator function didn't mark it as finished
            if (self.state == .finished) return null;

            var result: T = undefined;
            @memcpy(std.mem.asBytes(&result), &self.result);
            return result;
        }

        inline fn switch_context(from: *Context, to: *Context) void {
            // leaq 0f sets to the next '0' label after the current rip. (Which is at the end of this block.)
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
                : .{ .rax = true, .rcx = true, .rdx = true, .rbx = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .mm0 = true, .mm1 = true, .mm2 = true, .mm3 = true, .mm4 = true, .mm5 = true, .mm6 = true, .mm7 = true, .zmm0 = true, .zmm1 = true, .zmm2 = true, .zmm3 = true, .zmm4 = true, .zmm5 = true, .zmm6 = true, .zmm7 = true, .zmm8 = true, .zmm9 = true, .zmm10 = true, .zmm11 = true, .zmm12 = true, .zmm13 = true, .zmm14 = true, .zmm15 = true, .zmm16 = true, .zmm17 = true, .zmm18 = true, .zmm19 = true, .zmm20 = true, .zmm21 = true, .zmm22 = true, .zmm23 = true, .zmm24 = true, .zmm25 = true, .zmm26 = true, .zmm27 = true, .zmm28 = true, .zmm29 = true, .zmm30 = true, .zmm31 = true, .fpsr = true, .fpcr = true, .mxcsr = true, .rflags = true, .dirflag = true, .memory = true });
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.stack.deinit();
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

fn allocating(y: Yielder(u64), allocator: Allocator) void {
    const allocated = allocator.alloc(u8, 4) catch unreachable;
    defer allocator.free(allocated);

    @memset(allocated, 0);
    for (0..allocated.len) |i| {
        y.yield(allocated[i] + i);
    }
}

test "Generator General" {
    var generator: *Generator(fib, u64) = try .init(std.testing.allocator, .{4});
    defer generator.deinit(std.testing.allocator);

    std.debug.assert(generator.next() == 0);
    std.debug.assert(generator.next() == 1);
    std.debug.assert(generator.next() == 1);
    std.debug.assert(generator.next() == 2);
    std.debug.assert(generator.next() == 3);
    std.debug.assert(generator.next() == null);
}

test "Generator Allocating" {
    var generator: *Generator(allocating, u64) = try .init(std.testing.allocator, .{std.testing.allocator});
    defer generator.deinit(std.testing.allocator);

    std.debug.assert(generator.next() == 0);
    std.debug.assert(generator.next() == 1);
    std.debug.assert(generator.next() == 2);
    std.debug.assert(generator.next() == 3);
    std.debug.assert(generator.next() == null);
}
