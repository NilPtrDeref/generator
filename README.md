# generator

A generator coroutine library that works similarly to Pythons. It allows users
to run a function on another stack and yield return values to the caller.

## Support

Currently, this only supports x86_64 on linux. There may be support added for
other architectures and other operating systems in the future, but that is
unlikely, as this was mostly a fun/learning project.

For a fuller implementation of coroutines, check out [lalinsky/coro.zig](https://github.com/lalinsky/coro.zig/tree/main)
