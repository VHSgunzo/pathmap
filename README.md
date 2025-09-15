# path-mapping.so / pathmap
User-space path remapping via LD_PRELOAD library and a ptrace-based tracer. Similar to bind mounts, but per-process and without root.

Note: This is a practical hack that rewrites path arguments. Side effects or crashes are possible. Do not use for mission‑critical systems.

## Examples

### Example 1. Multiple versions via wrapper
```bash
#!/bin/bash
# /modules/someprogram/v2019/wrapper/someprogram
PATH_MAPPING="/usr/share/someprogram:/modules/someprogram/v2019/share/someprogram" \
  LD_PRELOAD=/path/to/path-mapping.so \
  /modules/someprogram/v2019/bin/someprogram
```
Put `/modules/someprogram/v2019/wrapper` on `PATH` and users can launch the desired version without editing the binary.

### Example 2. Redirect hard-coded paths into HOME
```bash
PATH_MAPPING="/usr/share/someprogram:$HOME/.local/share/someprogram" \
  LD_PRELOAD=/path/to/path-mapping.so \
  someprogram
```
Access to `/usr/share/someprogram/...` is transparently redirected to `$HOME/.local/share/someprogram/...`.

## How it works
The LD_PRELOAD library intercepts libc functions that take path arguments (`open*`, `stat*`, `exec*`, `scandir*`, `glob*`, xattr, `link*`, `rename*`, `mkdir*`, `mk*temp`, parts of mount API, inotify/fanotify, etc.).

- Before matching, paths are normalized: `.`/`..` collapsed; duplicate slashes removed. Relative paths are resolved against process CWD, for `*at` variants against `dirfd` (via `/proc/self/fd/<dirfd>`).
- `*at` functions get an absolute path prior to mapping.
- Builds on glibc and musl; some GNU-only variants are compiled only under `__GLIBC__`.

## Configuration

- `PATH_MAPPING` provides pairs in the form `FROM:TO[,FROM:TO...]`:
  ```bash
  export PATH_MAPPING="/usr/virtual1:/map/dest1,/usr/virtual2:/map/dest2"
  ```
- If unset/empty, both the library and the tracer use the same built-in default pairs from `pathmap_common.h` (test defaults).

### Exclusions
Skip mapping for sensitive prefixes via `PATH_MAPPING_EXCLUDE` (comma-separated absolute prefixes):
```bash
export PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev"
export PATH_MAPPING_EXCLUDE="/etc/passwd,/etc/group,/etc/nsswitch.conf"

# Tracer
PATH_MAPPING_EXCLUDE="/etc/passwd,/etc/group,/etc/nsswitch.conf" \
  PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev" ./pathmap bash

# LD_PRELOAD
PATH_MAPPING_EXCLUDE="/etc/passwd,/etc/group,/etc/nsswitch.conf" \
  PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev" LD_PRELOAD=./path-mapping.so bash
```
Defaults apply if not set: `/etc/passwd,/etc/group,/etc/nsswitch.conf`.

### Symlink resolution
By default the library does not resolve symlinks post-mapping. Enable post‑resolution with `PATHMAP_RELSYMLINK=1`.

- With `PATHMAP_RELSYMLINK=1`, if the mapped real path is a symlink, it is resolved before calling the original function. Relative symlink targets are interpreted relative to the original virtual directory and re‑mapped. `readlink`/`readlinkat` are never post‑processed.
- Applies to both the library and the tracer.

Examples:
```bash
PATHMAP_RELSYMLINK=1 PATH_MAPPING="/opt/virtual:/real/root" LD_PRELOAD=./path-mapping.so app
PATHMAP_RELSYMLINK=1 PATH_MAPPING="/opt/virtual:/real/root" ./pathmap -- app
```

## Build and install
```bash
make                 # glibc (default)
CC=musl-gcc make     # musl build
make test
```
Example run:
```bash
export PATH_MAPPING=/somewhere:$HOME
LD_PRELOAD=$PWD/path-mapping.so /bin/ls /somewhere
```

## Runtime logging
`PATHMAP_DEBUG` controls verbosity:
- `0` — quiet (default)
- `1` — info
- `2` — debug (per-call traces) (only for library)

Compile-time `DISABLE_*` macros can exclude specific overrides; see `path-mapping.c`.

## Tests
`make test` runs the integration tests under `test/`.

## LD_PRELOAD vs ptrace tracer differences

- Reverse mapping:
  - Library: does not post‑process `readlink*`; selectively adjusts names in `readdir64` when the new name fits; `getcwd` family is left as-is (see code).
  - Tracer: reverse‑maps `getcwd`, `readlink*` (adjusts returned length if truncated), and `getdents*` (in‑place rename when the new name fits).
- Relative paths:
  - Library: resolves via `/proc/self/fd/...` and normalizes.
  - Tracer: resolves in the tracee context via `/proc/<pid>/fd/...`.
- argv[0]:
  - Both update `argv[0]` automatically when executing a mapped path (important for apps deriving their path from `argv[0]`, e.g. `busybox`).

## Tracer (pathmap) for static binaries and direct syscalls

Build (x86_64 default; aarch64 and riscv64 supported):
```bash
make pathmap             # dynamic
make pathmap-static      # static
make pathmap-static-pie  # static-pie
```

Usage:
```bash
PATH_MAPPING="/etc:/tmp/etc,/dev:/tmp/dev" ./pathmap /bin/ldconfig
PATH_MAPPING="/etc:/tmp/etc" ./pathmap --exclude "/etc/passwd,/etc/group,/etc/nsswitch.conf" bash
./pathmap --help
```

Details:
- Architectures: x86_64, aarch64 (ARM64), riscv64.
- Intercepts pre‑call: `open`, `openat`, `openat2`, `newfstatat`, `unlinkat`, `execve/execveat`, `statx`, `rename*`, `link*`, `mkdir*`, `mknod*`, `mkfifo*`, `chmod`, `lchown`, `fchownat`, `utimensat`, `access`/`faccessat`, `open_tree`, `move_mount`, and more.
- Reverse mapping post‑call: `getcwd`, `readlink*`, `getdents*` (rename d_name in place when it fits).
- Handles longer mapped paths by placing strings on the tracee stack and updating registers.
- Follows `fork`/`vfork`/`clone`/`exec`.
- CLI/env: `-p/--path-mapping` or `PATH_MAPPING`, `-x/--exclude` or `PATH_MAPPING_EXCLUDE`, `-d/--debug` or `PATHMAP_DEBUG=1`, `-r/--dry-run`, `-h/--help`, `-v/--version`.

Defaults and logging:
- If `PATH_MAPPING` is empty, tracer uses the same built‑in default as the library.
- If `PATH_MAPPING_EXCLUDE`/`--exclude` are not provided, default exclusions apply.
- With debug on, logs which syscall triggered a remap, e.g. `[pathmap] map openat2: '/etc/ld.so.cache' -> '/tmp/etc/ld.so.cache'`.

Limitations:
- Not all syscalls/ioctls with path semantics are handled.
- `getdents*`: rename only when the new name is not longer than the original entry.
- `readlink*`: reverse‑mapped result is truncated to caller buffer; returned length is adjusted.
- aarch64: syscall numbers are not changed; only arguments/returns for supported calls are adjusted.
- This is not a security boundary; prefer bind/overlay mounts when available.

## Known caveats
1) Not a replacement for `mount --bind`. Static binaries and programs issuing direct syscalls won’t be affected by LD_PRELOAD (use the tracer).
2) “Virtual” entries may not appear in directory listings from the library alone; the tracer partially compensates via `getdents*` post‑processing.
3) Relative symlinks crossing mapping boundaries may not behave as expected unless `PATHMAP_RELSYMLINK=1` is set.
4) Functions resolved manually from `libc.so` via `dlopen`/`dlsym` bypass LD_PRELOAD.
5) Changes in libc internals may break interception in the future.

## License
MIT — see `LICENSE`.
