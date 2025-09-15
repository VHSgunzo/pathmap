# ld-preload-open / path-mapping.so
This library can trick a process into opening absolute paths from a different location, similar to bind mounts, but without root access.
The main difference that an affected process can (apparently) see and access files *inside* the virtual mapped directory, but cannot see the virtual directory *itself*.
Also, in contrast to mounts, every process on a system can have its own mapping (disregarding mount namespaces in current kernels, which basically also require root access).

## Example 1

One example are ["Environment Modules"](https://modules.readthedocs.io/en/latest/) which can be loaded with the command `module load` to activate some software in the current shell. If you have multiple versions of a software, which should be available side by side, you can use this library to trick them into loading version specific assets from a common absolute path.

Imagine you are an admin and would like to provide both version 2019 and version 2021 of `someprogram` to your users.
However, `someprogram` loads a file from a hard-coded path `/usr/share/someprogram/assets`, but different versions of the program ship with different versions of the file `/usr/share/someprogram/assets`.

By creating a wrapper script which runs the original program with `path-mapping.so`, you can force each version to load its own version, without altering the executable binary:

```bash
#!/bin/bash
# in file /modules/someprogram/v2019/wrapper/someprogram
PATH_MAPPING="/usr/share/someprogram:/modules/someprogram/v2019/share/someprogram" \
  LD_PRELOAD=/path/to/path-mapping.so \
  /modules/someprogram/v2019/bin/someprogram
```

Then just add `/modules/someprogram/v2019/wrapper` to `PATH` in your module definition file for version 2019 of `someprogram` and your users will be able to load it with `module load someprogram/2019` and run the wrapper script as `someprogram`.

## Example 2

Another example use-case might be to run a program with hard-coded paths from your home folder.
Imagine, `someprogram` tries to load files from `/usr/share/someprogram`, with no way to configure that path (apart from re-compiling, *if* you have the source code at all).
If you can't put the files there (for whatever reason), you could place them in `$HOME/.local/share/someprogram` instead.

With the following command, when the program tries to open e.g. `/usr/share/someprogram/icons.png` (which does not exist),
`path-mapping.so` would intercept that file access and rewrite the path to `$HOME/.local/share/someprogram/icons.png`, which does exist:
```bash
PATH_MAPPING="/usr/share/someprogram:$HOME/.local/share/someprogram" \
  LD_PRELOAD=/path/to/path-mapping.so \
  someprogram
```

## How it works

The path mapping works by intercepting standard library functions which have a path argument, like `open` or `chmod`.
If this argument matches the given prefix (the first part) of the mapping, the prefix is replaced by the destination (the second part) of the mapping.
Then the original standard library function is called with this possibly modified path.

- Relative paths are now supported: before matching, paths are normalized by resolving `.` and `..` and by anchoring relative paths to the process CWD (for `*at` functions: to the directory identified by `dirfd`).
- Reverse mapping for `getcwd` family: `getcwd`, `get_current_dir_name` and `getwd` will translate the real current directory back into the virtual path when applicable.
- `*at` functions: when the path is relative, the library resolves `dirfd` via `/proc/self/fd/<dirfd>` to compute an absolute path and then applies mapping.

Most Linux `libc` functions that operate on paths are supported, including many GNU and Linux-specific variants. The list is long (see code), covering e.g. `open*`, `stat*`, `exec*`, `scandir*`, `glob*`, xattr, `link*`, `rename*`, `mkdir*`, `mk*temp`, mount-related syscalls, inotify/fanotify, and more. Some exotic or deprecated variants are compiled conditionally under `__GLIBC__` for musl compatibility.

## Path mapping configuration

There are two ways to specify the path mappings. An arbitrary number of mappings can be used at once.

1. If the environment variable `PATH_MAPPING` exists, path-mapping.so will try to initialize the mappings from there.
   Use `:` to separate elements within a pair and `,` to separate pairs: `FROM1:TO1,FROM2:TO2,...`.
   ```bash
   export PATH_MAPPING="/usr/virtual1:/map/dest1,/usr/virtual2:/map/dest2"
   ```

### Excluding paths from mapping

Both LD_PRELOAD library and the `pathmap` tracer support exclusions via a comma-separated list of absolute prefixes in the environment variable `PATH_MAPPING_EXCLUDE`.

Behavior:
- If a path (after normalization and relative resolution) starts with any excluded prefix, forward mapping is skipped.
- Reverse mapping (for outputs like `getcwd`, `readlink*`, directory entry names) will also be skipped if the result would fall under an excluded prefix.

Examples:
```bash
# Do not remap NSS critical files while remapping everything else under /etc and /dev
export PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev"
export PATH_MAPPING_EXCLUDE="/etc/passwd,/etc/group,/etc/nsswitch.conf"

# Using the tracer
PATH_MAPPING_EXCLUDE="/etc/passwd,/etc/group,/etc/nsswitch.conf" \
  PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev" ./pathmap bash

# Using the LD_PRELOAD library
PATH_MAPPING_EXCLUDE="/etc/passwd,/etc/group,/etc/nsswitch.conf" \
  PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev" LD_PRELOAD=./path-mapping.so bash
```

2. If `PATH_MAPPING` is unset or empty, the mapping specified in the variable `default_path_map` will be used instead.
   The `pathmap` tracer mirrors this behavior with the same built-in default pair, so both tools behave consistently without `PATH_MAPPING`.
   You can modify it if you don't want to set `PATH_MAPPING`, for example like this:
   ```C
   static const char *default_path_map[][2] = {
       { "/usr/virtual1", "/map/dest1" },
       { "/usr/virtual1", "/map/dest2" },
   };
   ```

## Compiling and installation

Just run `make` to build the library and tracer.

Choose one of those files and place it anywhere convenient.
Note its absolute path and provide it to the target program as `LD_PRELOAD`, for example:

```bash
cd $HOME/repos/
git clone https://github.com/fritzw/ld-preload-open.git
cd ld-preload-open
make all
make test
export PATH_MAPPING=/somewhere:/$HOME
LD_PRELOAD=$HOME/repos/ld-preload-open/path-mapping.so /bin/ls /somewhere
# This should print something like the following:
# PATH_MAPPING[0]: /somewhere => /home/you
# Mapped Path: __xstat('/somewhere') => '/home/you'
# Mapped Path: opendir('/somewhere') => '/home/you'
# ... followed by the contents of your home directory.
```


### Building with musl or glibc

This project supports building against both glibc and musl.

- glibc (default):
  ```bash
  make
  ```
- musl:
  ```bash
  CC=musl-gcc make
  ```

Notes:
- Some GNU-only wrappers are compiled only when `__GLIBC__` is present (e.g., certain `__xstat*`, FTW, some 64-bit legacy aliases). Feature parity for core functionality is maintained on both libcs.
- If you see benign warnings about discarded qualifiers for `mk*temp` family, they can be ignored; the templates are copied internally.

## Runtime logging control (LD_PRELOAD library)

Use the environment variable `PATHMAP_DEBUG` to control logging verbosity at runtime:

- `PATHMAP_DEBUG=0` (default): quiet mode; no info/debug logs
- `PATHMAP_DEBUG=1`: info logs (e.g., mapping pairs at startup, mapped path notifications)
- `PATHMAP_DEBUG=2`: debug logs (includes info plus per-call traces of overridden functions)

Example:
```bash
PATHMAP_DEBUG=1 PATH_MAPPING="/etc:/tmp/etc" LD_PRELOAD=./path-mapping.so cmd
PATHMAP_DEBUG=2 PATH_MAPPING="/etc:/tmp/etc" LD_PRELOAD=./path-mapping.so cmd
```

Compile-time `DISABLE_*` macros are supported to exclude specific overrides. See `path-mapping.c` for available flags.

## Tests

Run `make test` to execute the included test suite.
Most things should be tested, but multiple variants of the same function are usually not tested separately.

## Potential problems

On first glance, this library might look like it can be used as a replacement for `mount --bind`.
However, since this is quite a hacky solution that runs only in user space, there are some issues where things do not work quite as one would expect.
Some of these could be fixed or worked around, but in some cases that would require significantly more work than just overloading a few functions.

1. Return values from standard library functions are not mapped universally.
   Only `getcwd` family is reverse-mapped in the LD_PRELOAD library. The `ptrace` tracer augments this by reverse-mapping `readlink/readlinkat` outputs and directory entries (`getdents`/`getdents64`) when feasible (name not longer than the original buffer space), and by reverse-mapping `getcwd`.
3. Virtual mapped entries do not appear in directory listings (LD_PRELOAD).
   The example mapping for `/usr/virtual1` will not show up in `ls /usr` or `find /usr`.
   The `ptrace` tracer partially mitigates this by post-processing `getdents` buffers and renaming `d_name` in-place if the new name is not longer than the old one.
4. Symlinks that point into virtual directories will not work with LD_PRELOAD, because symlinks are evaluated by the kernel, not in user space.
   For example, the following will fail:
   ```bash
   export PATH_MAPPING=/tmp/virtual:/tmp/real
   export LD_PRELOAD=/path/to/path-mapping.so
   mkdir /tmp/real
   touch /tmp/real/file
   ln -s /tmp/virtual /tmp/link
   ls -l /tmp/virtual/file # works
   ls -l /tmp/link/file # fails because kernel can not see `/tmp/virtual`
   ```
5. Creating relative symlinks that cross a mapping boundary will not work as expected:
   ```bash
   export PATH_MAPPING=/tmp/1/virtual:/tmp/real
   export LD_PRELOAD=/path/to/path-mapping.so
   mkdir /tmp/real
   echo content >/tmp/realfile
   ln -s ../../realfile /tmp/1/virtual/virtuallink
   cat /tmp/1/virtual/virtuallink # fails because /realfile does not exist
   ```
   The created link *would* point to `/tmp/realfile`, if `/tmp/1/virtual/` was a real directory.
   But since the symlink is evaluated relative to `/tmp/real`, it will actually point to `/realfile`, which does not exist.
6. If a programs manually loads a function like `fopen` from `libc.so` using `ldopen` and `dlsym`, then `LD_PRELOAD` can not intercept that.
   In this case, the path mapping will not work.
7. If a standard library function internally calls an overloaded function like `stat` or `open`, then `LD_PRELOAD` can not intercept that.
8. If internal workings of the libc change in the future, a program might just stop working.
9. Path mapping does not work if a program talks to the kernel directly using syscalls instead of going through `libc` wrappers, or for statically linked binaries. `LD_PRELOAD` is ineffective for static binaries (e.g., some `ldconfig` builds). Use the `ptrace` tracer below for such cases.

## Developer notes
- A ptrace-based tracer `pathmap` is provided to support static binaries. It rewrites path arguments of selected syscalls, with safe in-place writes or stack-based remapped buffers when the mapped path is longer.

## PTrace tracer (static binaries)

Build (x86_64 default, supports aarch64 and riscv64 via cross-compiling toolchains):
```bash
make pathmap           # dynamic
make pathmap-static    # static
make pathmap-static-pie
```

Usage:
```bash
PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev" ./pathmap --debug /bin/ldconfig
PATH_MAPPING="/etc:/tmp/etc" ./pathmap --exclude "/etc/passwd,/etc/group,/etc/nsswitch.conf" bash
./pathmap --help
```

Details:
- Architectures: x86_64, aarch64 (ARM64), riscv64 (via ptrace GETREGS/GETREGSET abstraction).
- Intercepts and remaps many path-taking syscalls pre-call: `open`, `openat`, `newfstatat`, `unlinkat`, `execve`, `statx`, `rename*`, `link*`, `mkdir*`, `mknod*`, `mkfifo*`, `chmod`, `lchown`, `fchownat`, `utimensat`, `access`, `faccessat`, `open_tree`, `move_mount`.
- Reverse mapping post-call: `getcwd`, `readlink/readlinkat` (adjusts return length if truncated), `getdents/getdents64` (in-place rename when new name fits).
- Relative paths are resolved in the tracee context (CWD or `dirfd` via `/proc/<pid>/fd/<fd>`), then normalized and mapped.
- Longer mapped paths are handled using safe stack-based placement in the tracee, with register arguments updated accordingly.
- Multi-process/thread: follows `fork`/`vfork`/`clone`/`exec`.
- CLI and env:
  - `-p, --path-mapping FROM:TO[,FROM:TO...]` (overrides `PATH_MAPPING`)
  - `-x, --exclude PREFIX[,PREFIX...]` (overrides `PATH_MAPPING_EXCLUDE`)
  - `-d, --debug` or `PATHMAP_DEBUG=1` for verbose logs
  - `-r, --dry-run` to log without modifying the tracee
  - `-h, --help`, `-v, --version`

Defaults and logging:
- If `PATH_MAPPING` is unset/empty, `pathmap` uses the same built-in default mapping as the LD_PRELOAD library.
- If `PATH_MAPPING_EXCLUDE`/`--exclude` are not provided, both tools apply default exclusions: `/etc/passwd,/etc/group,/etc/nsswitch.conf`.
- With debug enabled, `pathmap` prints which syscall triggered a remap, e.g. `[pathmap] map openat2: '/etc/ld.so.cache' -> '/tmp/etc/ld.so.cache'`.

Limitations:
- Some syscalls or ioctl paths not explicitly handled may still bypass mapping.
- For `getdents*`, reverse rename is only applied if the new name is not longer than the original entry; otherwise original names remain.
- For `readlink*`, if the reverse-mapped path exceeds caller buffer, the result is truncated and return length adjusted accordingly.
- On aarch64, changing the syscall number itself may require `NT_ARM_SYSTEM_CALL`; this tracer does not change syscall numbers, only arguments/returns for supported calls.
- Security hardening like strict user namespaces is out of scope; prefer bind/overlay when available.

## License

This repository is released unter the MIT license, see the file LICENSE for details.
