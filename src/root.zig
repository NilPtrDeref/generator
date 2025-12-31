const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;

// TODO: Clean up and learn how all of this works. For some reason, zig allocation takes a LOT of stack memory apparently.

pub threadlocal var current_context: ?*Context = null;
threadlocal var altstack_installed: bool = false;
threadlocal var altstack_mem: ?[]u8 = null;
var signal_handler_refcount: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var old_sigsegv_action: posix.Sigaction = undefined;
var old_sigbus_action: posix.Sigaction = undefined;

pub fn setupStackGrowth() !void {
    const altstack_size = switch (builtin.os.tag) {
        .linux => std.os.linux.SIGSTKSZ,
        else => std.c.SIGSTKSZ,
    };

    // Setup alternate stack for this thread if not already done
    if (!altstack_installed) {
        const mem = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(page_size), altstack_size);
        errdefer std.heap.page_allocator.free(mem);

        var stack = posix.stack_t{
            .flags = 0,
            .sp = mem.ptr,
            .size = altstack_size,
        };

        try posix.sigaltstack(&stack, null);

        altstack_mem = mem;
        altstack_installed = true;
    }

    // Install global signal handler (once per process)
    // Increment refcount; if this is the first caller, install the handler
    const prev_refcount = signal_handler_refcount.fetchAdd(1, .acquire);
    if (prev_refcount == 0) {
        var sa = posix.Sigaction{
            .handler = .{ .sigaction = stackFaultHandler },
            .mask = posix.sigemptyset(),
            .flags = posix.SA.SIGINFO | posix.SA.ONSTACK,
        };

        posix.sigaction(posix.SIG.SEGV, &sa, &old_sigsegv_action);

        // macOS sends SIGBUS for PROT_NONE access, not SIGSEGV
        if (builtin.os.tag.isDarwin()) {
            posix.sigaction(posix.SIG.BUS, &sa, &old_sigbus_action);
        }
    }
}

pub fn cleanupStackGrowth() void {
    // Windows has nothing to clean up
    if (builtin.os.tag == .windows) return;

    if (altstack_installed) {
        // Disable alternate stack
        var disable_stack = posix.stack_t{
            .flags = std.posix.system.SS.DISABLE,
            .sp = undefined,
            .size = 0,
        };
        posix.sigaltstack(&disable_stack, null) catch {
            // Best effort - can't do much if this fails
        };

        // Free the alternate stack memory
        if (altstack_mem) |mem| {
            std.heap.page_allocator.free(mem);
            altstack_mem = null;
        }

        altstack_installed = false;
    }

    // Decrement refcount; if this was the last thread, uninstall the handler
    const prev_refcount = signal_handler_refcount.fetchSub(1, .release);
    if (prev_refcount == 1) {
        // We were the last thread - restore the old signal handlers
        posix.sigaction(posix.SIG.SEGV, &old_sigsegv_action, null);
        if (builtin.os.tag.isDarwin()) {
            posix.sigaction(posix.SIG.BUS, &old_sigbus_action, null);
        }
    }
}

inline fn getFaultAddress(info: *const posix.siginfo_t) usize {
    return @intFromPtr(switch (builtin.os.tag) {
        .linux => info.fields.sigfault.addr,
        .macos, .ios, .tvos, .watchos, .visionos => info.addr,
        .freebsd, .dragonfly => info.addr,
        .netbsd => info.info.reason.fault.addr,
        .solaris, .illumos => info.reason.fault.addr,
        else => @compileError("Stack growth not supported on this platform"),
    });
}
fn stackExtendPosix(info: *StackInfo) error{StackOverflow}!void {
    const chunk_size = 64 * 1024;
    const growth_factor_num = 3;
    const growth_factor_den = 2;

    // Calculate current committed size
    const current_committed = info.base - info.limit;

    // Calculate new committed size (1.5x current)
    const new_committed_size = (current_committed * growth_factor_num) / growth_factor_den;
    const additional_size = new_committed_size - current_committed;
    const size_to_commit = std.mem.alignForward(usize, additional_size, chunk_size);

    // Calculate new limit (stack grows downward from high to low address)
    // Check if we have enough uncommitted space
    if (size_to_commit > info.limit) {
        return error.StackOverflow;
    }
    const new_limit = info.limit - size_to_commit;

    // Check we don't overflow into guard page
    const guard_end = @intFromPtr(info.allocation_ptr) + page_size;
    if (new_limit < guard_end) {
        return error.StackOverflow;
    }

    // Commit the memory region
    const commit_start = std.mem.alignBackward(usize, new_limit, page_size);
    const commit_size = info.limit - commit_start;
    const addr: [*]align(page_size) u8 = @ptrFromInt(commit_start);
    posix.mprotect(addr[0..commit_size], posix.PROT.READ | posix.PROT.WRITE) catch {
        return error.StackOverflow;
    };

    // Update limit to new bottom of committed region
    info.limit = commit_start;
}

fn stackFaultHandler(sig: c_int, info: *const posix.siginfo_t, ctx: ?*anyopaque) callconv(.c) void {
    const fault_addr = getFaultAddress(info);

    // Get current_context from coroutines module
    const current_ctx = current_context orelse {
        // Not in a coroutine context - propagate to previous handler
        invokePreviousHandler(sig, info, ctx);
    };

    const stack_info = &current_ctx.stack_info;

    // Check if allocation_ptr is null (not our stack)
    if (@intFromPtr(stack_info.allocation_ptr) == 0) {
        invokePreviousHandler(sig, info, ctx);
    }

    // Stack layout: [guard_page][uncommitted][committed]
    const stack_base = @intFromPtr(stack_info.allocation_ptr);
    const guard_page_end = stack_base + page_size;
    const uncommitted_start = guard_page_end;
    const uncommitted_end = stack_info.limit;

    // Check if fault is in guard page (true stack overflow)
    if (fault_addr >= stack_base and fault_addr < guard_page_end) {
        abortOnStackOverflow(fault_addr, stack_info);
    }

    // Check if fault is in uncommitted region (automatic growth)
    if (fault_addr >= uncommitted_start and fault_addr < uncommitted_end) {
        // Fault is in uncommitted region - extend the stack
        stackExtendPosix(stack_info) catch {
            // Extension failed - this is a stack overflow
            abortOnStackOverflow(fault_addr, stack_info);
        };
        // Stack extended successfully - return to resume execution
        return;
    }

    // Fault is not in our stack region - propagate to previous handler
    invokePreviousHandler(sig, info, ctx);
}

fn invokePreviousHandler(sig: c_int, info: *const posix.siginfo_t, ctx: ?*anyopaque) noreturn {
    // Get the appropriate old sigaction based on signal number
    const old_sa = if (sig == posix.SIG.SEGV) &old_sigsegv_action else &old_sigbus_action;

    // Check if the old handler had SA_SIGINFO flag set
    if ((old_sa.flags & posix.SA.SIGINFO) != 0) {
        // Previous handler was a sigaction-style handler
        if (old_sa.handler.sigaction) |sa| {
            sa(sig, info, ctx);
        }
    } else {
        // Previous handler was a simple handler (or SIG_DFL/SIG_IGN)
        if (old_sa.handler.handler) |h| {
            if (h == posix.SIG.DFL or h == posix.SIG.IGN) {
                // Restore the previous handler and re-raise the signal
                // We must restore the handler first, otherwise the signal comes back to us
                posix.sigaction(@intCast(sig), old_sa, null);
                _ = posix.raise(@intCast(sig)) catch {};
            } else {
                // Call the previous simple handler
                h(sig);
            }
        }
    }

    // If we reach here, either raise failed or the handler returned
    // In either case, abort
    posix.abort();
}
fn abortOnStackOverflow(fault_addr: usize, stack_info: *const StackInfo) noreturn {
    var buf: [300]u8 = undefined;

    const stack_base = @intFromPtr(stack_info.allocation_ptr);
    const stack_size = stack_info.allocation_len;
    const committed = stack_info.base - stack_info.limit;
    const is_guard_page_fault = fault_addr >= stack_base and fault_addr < stack_base + page_size;

    const msg = std.fmt.bufPrint(
        &buf,
        "Coroutine stack overflow!\n" ++
            "  Fault address:    0x{x}\n" ++
            "  Stack base:       0x{x}\n" ++
            "  Stack size:       {d} KB\n" ++
            "  Committed:        {d} KB\n" ++
            "  Guard page fault: {}\n",
        .{
            fault_addr,
            stack_base,
            stack_size / 1024,
            committed / 1024,
            is_guard_page_fault,
        },
    ) catch "Coroutine stack overflow (error formatting message)\n";

    _ = posix.write(posix.STDERR_FILENO, msg) catch {};
    posix.abort();
}

pub const page_size = std.heap.page_size_min;
pub const StackInfo = extern struct {
    allocation_ptr: [*]align(page_size) u8, // deallocation_stack on Windows (TEB offset 0x1478)
    base: usize, // stack_base on Windows (TEB offset 0x08)
    limit: usize, // stack_limit on Windows (TEB offset 0x10)
    allocation_len: usize,
    valgrind_stack_id: usize = 0,
};

// Platform-specific macros for declaring future mprotect permissions
// NetBSD PROT_MPROTECT: Required when PaX MPROTECT is enabled to allow permission escalation
// FreeBSD PROT_MAX: Optional security feature to restrict maximum permissions
// See: https://man.netbsd.org/mmap.2 and https://man.freebsd.org/mmap.2
inline fn PROT_MAX_FUTURE(prot: u32) u32 {
    return switch (builtin.os.tag) {
        .netbsd => prot << 3, // PROT_MPROTECT
        .freebsd => prot << 16, // PROT_MAX
        else => 0,
    };
}
pub fn stackAlloc(info: *StackInfo, maximum_size: usize, committed_size: usize) error{OutOfMemory}!void {
    // Ensure we allocate at least 2 pages (guard + usable space)
    const min_pages = 2;
    // Add guard page to maximum_size to get total allocation size
    const adjusted_size = @max(maximum_size + page_size, page_size * min_pages);

    const size = std.math.ceilPowerOfTwo(usize, adjusted_size) catch |err| {
        std.log.err("Failed to calculate stack size: {}", .{err});
        return error.OutOfMemory;
    };

    // Reserve address space with PROT_NONE
    // On NetBSD/FreeBSD, we must declare future permissions upfront for security policies
    const prot_flags = posix.PROT.NONE | PROT_MAX_FUTURE(posix.PROT.READ | posix.PROT.WRITE);

    // MAP_STACK is supported on Linux and NetBSD, but not on macOS/FreeBSD
    var map_flags = posix.MAP{ .TYPE = .PRIVATE, .ANONYMOUS = true };
    if (builtin.os.tag == .linux or builtin.os.tag == .netbsd) {
        map_flags.STACK = true;
    }

    const allocation = posix.mmap(
        null, // Address hint (null for system to choose)
        size,
        prot_flags,
        map_flags,
        -1, // File descriptor (not applicable)
        0, // Offset within the file (not applicable)
    ) catch |err| {
        std.log.err("Failed to allocate stack memory: {}", .{err});
        return error.OutOfMemory;
    };
    errdefer posix.munmap(allocation);

    // Advise kernel not to use transparent huge pages (Linux-specific optimization)
    // THP can cause memory bloat for small/sparse stack allocations
    if (builtin.os.tag == .linux) {
        _ = posix.madvise(allocation.ptr, allocation.len, posix.MADV.NOHUGEPAGE) catch {};
    }

    // Guard page stays as PROT_NONE (first page)

    // Round committed size up to page boundary
    const commit_size = std.mem.alignForward(usize, committed_size, page_size);

    // Validate that committed size doesn't exceed available space (minus guard page)
    if (commit_size > size - page_size) {
        std.log.err("Committed size ({d}) exceeds maximum size ({d}) after alignment", .{ commit_size, size - page_size });
        return error.OutOfMemory;
    }

    // Commit initial portion at top of stack
    const stack_top = @intFromPtr(allocation.ptr) + size;
    const initial_commit_start = stack_top - commit_size;
    const initial_region: [*]align(page_size) u8 = @ptrFromInt(initial_commit_start);
    posix.mprotect(initial_region[0..commit_size], posix.PROT.READ | posix.PROT.WRITE) catch |err| {
        std.log.err("Failed to commit initial stack region: {}", .{err});
        return error.OutOfMemory;
    };

    // Stack layout (grows downward from high to low addresses):
    // [guard_page (PROT_NONE)][uncommitted (PROT_NONE)][committed (READ|WRITE)]
    // ^                                                ^                       ^
    // allocation_ptr                                   limit                   base (allocation_ptr + allocation_len)
    info.* = .{
        .allocation_ptr = allocation.ptr,
        .base = stack_top,
        .limit = initial_commit_start,
        .allocation_len = allocation.len,
    };

    if (builtin.mode == .Debug and builtin.valgrind_support) {
        const stack_slice: [*]u8 = @ptrFromInt(info.limit);
        info.valgrind_stack_id = std.valgrind.stackRegister(stack_slice[0 .. info.base - info.limit]);
    }
}
pub fn stackFree(info: StackInfo) void {
    if (builtin.mode == .Debug and builtin.valgrind_support) {
        if (info.valgrind_stack_id != 0) {
            std.valgrind.stackDeregister(info.valgrind_stack_id);
        }
    }

    const allocation: []align(page_size) u8 = info.allocation_ptr[0..info.allocation_len];
    posix.munmap(allocation);
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

        pub fn yield(self: Self, data: T) void {
            self.vtable.yield(self.ctx, data);
        }
    };
}

fn GeneratorEntrypoint() callconv(.naked) noreturn {
    asm volatile (
        \\ leaq 1f(%%rip), %%rax
        \\ pushq %%rax
        \\ movq 16(%%rsp), %%rdi
        \\ jmpq *8(%%rsp)
        \\1:
    );
}

const Context = struct {
    rsp: u64 = 0,
    rbp: u64 = 0,
    rip: u64 = 0,
    stack_info: StackInfo,
    pub const stack_alignment = 16;
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
        current: Context,
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

            try stackAlloc(&self.stack, 8 * 1024 * 1024, 8192); // At least 8192 required for zig allocation to work.
            errdefer stackFree(self.stack);

            const Entrypoint = extern struct {
                func: *const fn (*anyopaque) callconv(.c) noreturn,
                context: *anyopaque,
            };

            const Data = struct {
                g: *Self,
                args: *Args,

                fn start(context: *anyopaque) callconv(.c) noreturn {
                    const data: *@This() = @ptrCast(@alignCast(context));
                    // const current: *Context = asm volatile (
                    //     \\
                    //     : [ret] "={rcx}" (-> *Context),
                    // );
                    // const s: *Self = @fieldParentPtr("current", current);

                    @call(.auto, f, .{data.g.interface} ++ data.args.*);

                    // When the generator function returns, we should mark the Generator as finished and then switch back to the calling context
                    data.g.state = .finished;
                    Self.switch_context(&data.g.current, &data.g.idle);

                    unreachable;
                }
            };

            var stack_top = self.stack.base;
            const stack_limit = self.stack.limit;

            // Copy our wrapper to stack (allocate downward from top)
            stack_top = std.mem.alignBackward(usize, stack_top - @sizeOf(Data), @alignOf(Data));
            if (stack_top < stack_limit) @panic("Stack overflow during coroutine setup: not enough space for CoroutineData");
            const data: *Data = @ptrFromInt(stack_top);
            data.g = self;
            data.args = &self.args;

            // Allocate and configure structure for coroEntry
            stack_top = std.mem.alignBackward(usize, stack_top - @sizeOf(Entrypoint), Context.stack_alignment);
            if (stack_top < stack_limit) @panic("Stack overflow during coroutine setup: not enough space for Entrypoint");
            const entry: *Entrypoint = @ptrFromInt(stack_top);
            entry.func = &Data.start;
            entry.context = data;

            // Initialize stack
            // Prime the values that will be used if the function returns
            self.current.rbp = 0;
            self.current.rsp = stack_top;
            self.current.rip = @intFromPtr(&GeneratorEntrypoint);
            self.current.stack_info = self.stack;

            return self;
        }

        fn yield(ctx: *anyopaque, data: T) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            @memcpy(&self.result, std.mem.asBytes(&data));
            Self.switch_context(&self.current, &self.idle);
        }

        pub fn next(self: *Self) ?T {
            switch (self.state) {
                .ready => {
                    self.state = .running;
                    Self.switch_context(&self.idle, &self.current);
                },
                .running => {
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
            current_context = to;
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
                : .{
                  .rax = true,
                  .rcx = true,
                  .rdx = true,
                  .rbx = true,
                  .rsi = true,
                  .rdi = true,
                  .r8 = true,
                  .r9 = true,
                  .r10 = true,
                  .r11 = true,
                  .r12 = true,
                  .r13 = true,
                  .r14 = true,
                  .r15 = true,
                  .mm0 = true,
                  .mm1 = true,
                  .mm2 = true,
                  .mm3 = true,
                  .mm4 = true,
                  .mm5 = true,
                  .mm6 = true,
                  .mm7 = true,
                  .zmm0 = true,
                  .zmm1 = true,
                  .zmm2 = true,
                  .zmm3 = true,
                  .zmm4 = true,
                  .zmm5 = true,
                  .zmm6 = true,
                  .zmm7 = true,
                  .zmm8 = true,
                  .zmm9 = true,
                  .zmm10 = true,
                  .zmm11 = true,
                  .zmm12 = true,
                  .zmm13 = true,
                  .zmm14 = true,
                  .zmm15 = true,
                  .zmm16 = true,
                  .zmm17 = true,
                  .zmm18 = true,
                  .zmm19 = true,
                  .zmm20 = true,
                  .zmm21 = true,
                  .zmm22 = true,
                  .zmm23 = true,
                  .zmm24 = true,
                  .zmm25 = true,
                  .zmm26 = true,
                  .zmm27 = true,
                  .zmm28 = true,
                  .zmm29 = true,
                  .zmm30 = true,
                  .zmm31 = true,
                  .fpsr = true,
                  .fpcr = true,
                  .mxcsr = true,
                  .rflags = true,
                  .dirflag = true,
                  .memory = true,
                });
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            stackFree(self.stack);
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
    try setupStackGrowth();
    defer cleanupStackGrowth();

    var generator: *Generator(allocating, u64) = try .init(std.testing.allocator, .{std.testing.allocator});
    defer generator.deinit(std.testing.allocator);

    std.debug.assert(generator.next() == 0);
    std.debug.assert(generator.next() == 1);
    std.debug.assert(generator.next() == 2);
    std.debug.assert(generator.next() == 3);
    std.debug.assert(generator.next() == null);
}
