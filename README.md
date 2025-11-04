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

### Path Mapping Format

`PATH_MAPPING` provides pairs in the form `FROM:TO[,FROM:TO...]`:
```bash
export PATH_MAPPING="/usr/virtual1:/map/dest1,/usr/virtual2:/map/dest2"
```

#### Basic Examples
```bash
# Simple prefix mapping
PATH_MAPPING="/usr/share/app:/home/user/.local/share/app"

# Multiple mappings
PATH_MAPPING="/usr/share/app:/home/user/.local/share/app,/usr/bin/app:/home/user/.local/bin/app"

# Multi-line format (also supported)
PATH_MAPPING="/usr/share/app:/home/user/.local/share/app
/usr/bin/app:/home/user/.local/bin/app
/usr/lib/app:/home/user/.local/lib/app"
```

- If unset/empty, both the library and the tracer use the same built-in default pairs from `pathmap_common.h` (test defaults).

### Reverse mapping (virtualizing outputs)
By default reverse mapping is enabled and user-visible paths are virtualized (set in `pathmap_common.h`: `#define PM_DEFAULT_REVERSE_ENABLED 1`).

- `ls`/`readdir`/`getdents*`: directory entry names are rewritten back to the virtual names.
  - Special Case 2: virtual-root child normalization. If a mapping is `/app/usr -> /real/usr-123`, then `ls -1 /app` prints `usr` (not `usr-123`).
- `readlink -f` on virtual paths returns the virtualized absolute path.
- `pwd`/`getcwd` and `readlink /proc/<pid>/cwd` are virtualized to return the virtual CWD.
- Set `PATHMAP_REVERSE=0` to disable reverse mapping.

Examples (preload and tracer behave the same):
```bash
# Virtualize outputs (default)
PATH_MAPPING="/app:$PWD" LD_PRELOAD=$PWD/path-mapping.so ls -1 /app

# Tracer variants
PATH_MAPPING="/app:$PWD" ./pathmap -- ls -1 /app
```

### Exclusions

Skip mapping for sensitive prefixes via `PATH_MAPPING_EXCLUDE`:

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

### Glob Pattern Support and Parsing

#### Glob Pattern Support

**In Path Mappings (FROM patterns):**
- ✅ **`*` (asterisk)**: Supported with FNM_PATHNAME semantics
  - Matches any characters within a single path segment (doesn't cross `/` boundaries)
  - When `*` is followed by a literal (e.g., `*.mo`), it captures everything before that literal within the segment
  - When `*` is at the end of a pattern, it captures everything to the end of the input path (can span multiple segments)
  - Supports capture groups for substitution in TO patterns
  - Multiple `*` patterns are supported
  - Can match partial filenames (e.g., `qemu*` matches `qemu-system-x86_64`, `*.mo` matches files with `.mo` extension)
- ❌ **`?` (question mark)**: Not supported
- ❌ **`[ ]` (character classes)**: Not supported

**In Exclusions (PATH_MAPPING_EXCLUDE):**
- ✅ **Full glob support**: `*`, `?`, `[ ]`, and all standard glob patterns
- Uses standard `fnmatch()` with `FNM_PATHNAME` semantics

#### Examples

**Glob patterns in mappings:**
```bash
# ✅ Single asterisk - captures locale directory
PATH_MAPPING="/usr/share/locale/*:/tmp/AppDir/usr/share/locale/*"
# Maps: /usr/share/locale/en/LC_MESSAGES/app.mo -> /tmp/AppDir/usr/share/locale/en/LC_MESSAGES/app.mo

# ✅ Multiple asterisks - captures multiple segments
PATH_MAPPING="/usr/share/locale/*/*/app.mo:/tmp/AppDir/usr/share/locale/*/*/app.mo"
# Maps: /usr/share/locale/en/LC_MESSAGES/app.mo -> /tmp/AppDir/usr/share/locale/en/LC_MESSAGES/app.mo

# ✅ Partial filename matching with extension - captures prefix before extension
PATH_MAPPING="/usr/share/locale/*/*/*.mo:/tmp/AppDir/usr/share/locale/*/*/*.mo"
# Maps: /usr/share/locale/en/LC_MESSAGES/zenity.mo -> /tmp/AppDir/usr/share/locale/en/LC_MESSAGES/zenity.mo
# First '*' captures "en", second '*' captures "LC_MESSAGES", third '*' captures "zenity" (before .mo extension)

# ✅ Partial filename matching - captures suffix after prefix in filename
PATH_MAPPING="/usr/bin/qemu*:/tmp/qemu*"
# Maps: /usr/bin/qemu-system-x86_64 -> /tmp/qemu-system-x86_64
# Maps: /usr/bin/qemu-img -> /tmp/qemu-img
# The '*' captures everything after "qemu" in the filename and substitutes it in the target pattern

# ✅ Partial filename matching with multiple patterns
PATH_MAPPING="/usr/share/locale/en/*/app*:/tmp/AppDir/usr/share/locale/en/*/zenity*"
# Maps: /usr/share/locale/en/LC_MESSAGES/app.mo -> /tmp/AppDir/usr/share/locale/en/LC_MESSAGES/zenity.mo
# First '*' captures "LC_MESSAGES", second '*' captures ".mo"

# ✅ Multiple paths mapping to a single fixed target (no '*' in TO pattern)
PATH_MAPPING="/usr/*/qemu*:/tmp/qemu-system-x86_64"
# Maps: /usr/bin/qemu-system-i386 -> /tmp/qemu-system-x86_64
# Maps: /usr/bin/qemu-img -> /tmp/qemu-system-x86_64
# Maps: /usr/sbin/qemu-nbd -> /tmp/qemu-system-x86_64
# When TO pattern has no '*', captured parts are ignored and all matching paths map to the same fixed target
# Note: The '*' matches only a single path segment, so /usr/local/bin/qemu* would require a different pattern like /usr/*/bin/qemu* or /usr/*/*/qemu*

# ❌ These will NOT work as glob patterns (treated as literal paths):
PATH_MAPPING="/usr/share/locale/??/LC_MESSAGES:/tmp/AppDir/usr/share/locale/??/LC_MESSAGES"
PATH_MAPPING="/usr/share/locale/[a-z]*:/tmp/AppDir/usr/share/locale/[a-z]*"
```

**Glob patterns in exclusions:**
```bash
# ✅ Full glob support in exclusions
PATH_MAPPING_EXCLUDE="/proc/*/*,/sys/*,/tmp/test[0-9]*,/var/log/*.log"

# Examples of what gets excluded:
# /proc/self/cwd, /proc/1234/status
# /sys/kernel, /sys/devices
# /tmp/test1, /tmp/test2, /tmp/test9
# /var/log/app.log, /var/log/system.log
```

#### Parsing Rules

**Common parsing rules for both PATH_MAPPING and PATH_MAPPING_EXCLUDE:**
- **Separators**: Items separated by commas (`,`), newlines (`\n`), or carriage returns (`\r`)
- **Whitespace**: Leading and trailing spaces/tabs are automatically trimmed
- **Empty entries**: Empty items are skipped
- **Path normalization**: All paths are normalized (collapsed `.`/`..`, removed duplicate slashes)
- **Glob detection**: Patterns containing `*`, `?`, or `[` are automatically detected as glob patterns

**PATH_MAPPING specific:**
- **Format**: Each pair must be `FROM:TO` with exactly one colon
- **Required fields**: Both FROM and TO must be non-empty after trimming
- **Invalid pairs**: Pairs without `:` or with empty FROM/TO are silently skipped

#### Error Handling

- **Invalid pairs**: Pairs without `:` or with empty FROM/TO are silently skipped
- **Memory allocation failures**: Parsing stops gracefully, partial results may be available
- **Buffer overflow**: Paths longer than `MAX_PATH` (4096) are truncated
- **Empty input**: Falls back to built-in defaults without error

### Symlink resolution
By default the library does not resolve symlinks post-mapping. Enable post‑resolution with `PATHMAP_RELSYMLINK=1`.

- With `PATHMAP_RELSYMLINK=1`, if the mapped real path is a symlink, it is resolved before calling the original function. Relative symlink targets are interpreted relative to the original virtual directory and re‑mapped. `readlink`/`readlinkat` are never post‑processed.
- Applies to both the library and the tracer.

Examples:
```bash
PATHMAP_RELSYMLINK=1 PATH_MAPPING="/opt/virtual:/real/root" LD_PRELOAD=./path-mapping.so app
PATHMAP_RELSYMLINK=1 PATH_MAPPING="/opt/virtual:/real/root" ./pathmap -- app
```

### CWD virtualization
- On `getcwd()` and `readlink(/proc/<pid>/cwd)`, the returned path is rewritten back to the virtual path under reverse mapping.

Examples:
```bash
PATH_MAPPING="/app:$PWD" LD_PRELOAD=$PWD/path-mapping.so bash -lc 'cd /app; pwd -P'
# => /app

PATH_MAPPING="/app:$PWD" ./pathmap -- bash -lc 'cd /app; pwd -P'
# => /app
```

### Hiding a real directory by re-mapping it to /nowhere
You can effectively hide a real directory by re-mapping its real path to `/nowhere` while exposing it under a virtual mount point.

```bash
# Expose real content at /hidden, but any direct access to /real goes to /nowhere
PATH_MAPPING="/hidden:/real,/real:/nowhere" LD_PRELOAD=$PWD/path-mapping.so bash -lc "ls / && ls /hidden && ls /real || echo hidden"

# Tracer variant
PATH_MAPPING="/hide:/real,/real:/nowhere" ./pathmap -- bash -lc "ls / && ls /hide && ls /real || echo hidden"
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
- Handles longer mapped paths by placing strings on the tracee stack and updating registers.
- Follows `fork`/`vfork`/`clone`/`exec`.
- CLI/env: `-p/--path-mapping` or `PATH_MAPPING`, `-x/--exclude` or `PATH_MAPPING_EXCLUDE`, `-d/--debug` or `PATHMAP_DEBUG=1`, `-r/--dry-run`, `-h/--help`, `-v/--version`.

Defaults and logging:
- If `PATH_MAPPING` is empty, tracer uses the same built‑in default as the library.
- If `PATH_MAPPING_EXCLUDE`/`--exclude` are not provided, default exclusions apply.
- With debug on, logs which syscall triggered a remap, e.g. `[pathmap] map openat2: '/etc/ld.so.cache' -> '/tmp/etc/ld.so.cache'`.

Limitations:
- Not all syscalls/ioctls with path semantics are handled.
- aarch64: syscall numbers are not changed; only arguments/returns for supported calls are adjusted.
- This is not a security boundary; prefer bind/overlay mounts when available.

## Known caveats
1) Not a replacement for `mount --bind`. Static binaries and programs issuing direct syscalls won’t be affected by LD_PRELOAD (use the tracer).
2) Relative symlinks crossing mapping boundaries require `PATHMAP_RELSYMLINK=1` to behave as expected (applies to both preload and tracer).
3) Some libc-only functions are not hooked by the tracer (e.g. `realpath(3)`); tracer achieves similar behavior via syscalls. Tools relying purely on libc without issuing syscalls may differ subtly under the tracer.
4) Extended attributes: behavior depends on filesystem support and permissions. On some systems `l*xattr` on symlinks returns `EPERM` or `ENOTSUP`.
5) Mount API: `umount2`/mount-related calls typically require elevated privileges and are expected to fail for unprivileged users; interception only remaps path arguments.
6) Mapping real paths to non-directories (e.g. to `/nowhere`) can break programs that traverse those real paths directly. Prefer hiding via virtual mount-points and excludes.
7) Functions resolved manually from `libc.so` via `dlopen`/`dlsym` bypass LD_PRELOAD.
8) Changes in libc internals may break interception in the future.

## License
MIT — see `LICENSE`.
