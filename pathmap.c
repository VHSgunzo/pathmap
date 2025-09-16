#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include "pathmap_common.h"

// Intercepts path-taking syscalls via ptrace; some libc functions are handled indirectly through the underlying syscalls

#define MAX_PATH 4096
#ifndef PATHMAP_VERSION
#define PATHMAP_VERSION "0.2"
#endif

// Use common configuration structure
static struct pm_common_config g_config;
static const char *g_current_syscall = NULL; /* debug context */

static void cleanup_config(void)
{
    pm_cleanup_common_config(&g_config);
}

static int is_excluded_prefix(const char *abs_path)
{
    return pm_is_excluded_prefix(abs_path, &g_config.mapping_config);
}

static int read_string(pid_t pid, unsigned long addr, char *buf, size_t maxlen)
{
	struct iovec local = { .iov_base = buf, .iov_len = maxlen - 1 };
	struct iovec remote = { .iov_base = (void *)addr, .iov_len = maxlen - 1 };
	ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
	if (n <= 0) return -1;
	// ensure NUL-termination
	size_t i;
	for (i = 0; i < (size_t)n; i++) if (buf[i] == '\0') break;
	if (i == (size_t)n) buf[i] = '\0';
	return 0;
}

static int write_string_if_fits(pid_t pid, unsigned long addr, const char *s, size_t original_len)
{
	size_t newlen = strlen(s);
	if (newlen > original_len) return -1;
	struct iovec local = { .iov_base = (void *)s, .iov_len = newlen + 1 };
	struct iovec remote = { .iov_base = (void *)addr, .iov_len = newlen + 1 };
	ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
	return (n == (ssize_t)(newlen + 1)) ? 0 : -1;
}


// Forward declarations for functions used before their definitions
static void resolve_relative_for_pid(char *path, size_t path_size, pid_t pid, int dirfd);
static const char *apply_mapping(const char *in, char *out, size_t out_size);

// Write a string into the tracee's stack below RSP and return its address
#if defined(__x86_64__)
typedef struct user_regs_struct TraceRegs;
static inline int regs_read(pid_t pid, TraceRegs *r) { return ptrace(PTRACE_GETREGS, pid, NULL, r); }
static inline int regs_write(pid_t pid, const TraceRegs *r) { return g_config.dry_run ? 0 : ptrace(PTRACE_SETREGS, pid, NULL, (void *)r); }
static inline long get_sysno(const TraceRegs *r) { return (long)r->orig_rax; }
static inline unsigned long get_arg(const TraceRegs *r, int idx) {
    switch (idx) { case 0: return r->rdi; case 1: return r->rsi; case 2: return r->rdx; case 3: return r->r10; case 4: return r->r8; case 5: return r->r9; }
    return 0;
}
static inline void set_arg(TraceRegs *r, int idx, unsigned long v) {
    switch (idx) { case 0: r->rdi = v; break; case 1: r->rsi = v; break; case 2: r->rdx = v; break; case 3: r->r10 = v; break; case 4: r->r8 = v; break; case 5: r->r9 = v; break; }
}
static inline unsigned long get_sp(const TraceRegs *r) { return (unsigned long)r->rsp; }
static inline void set_retval(TraceRegs *r, unsigned long v) { r->rax = v; }
static inline unsigned long get_retval(const TraceRegs *r) { return r->rax; }
#elif defined(__aarch64__)
// aarch64: args x0..x5 in regs[0..5], sysno in regs[8], sp in sp, retval in regs[0]
typedef struct user_pt_regs TraceRegs;
static inline int regs_read(pid_t pid, TraceRegs *r) { struct iovec iov = { .iov_base = r, .iov_len = sizeof(*r) }; return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov); }
static inline int regs_write(pid_t pid, const TraceRegs *r) { if (g_config.dry_run) return 0; struct iovec iov = { .iov_base = (void *)r, .iov_len = sizeof(*r) }; return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov); }
static inline long get_sysno(const TraceRegs *r) { return (long)r->regs[8]; }
static inline unsigned long get_arg(const TraceRegs *r, int idx) { return (idx>=0 && idx<=5)? r->regs[idx] : 0; }
static inline void set_arg(TraceRegs *r, int idx, unsigned long v) { if (idx>=0 && idx<=5) r->regs[idx] = v; }
static inline unsigned long get_sp(const TraceRegs *r) { return (unsigned long)r->sp; }
static inline void set_retval(TraceRegs *r, unsigned long v) { r->regs[0] = v; }
static inline unsigned long get_retval(const TraceRegs *r) { return r->regs[0]; }
#elif defined(__riscv) && __riscv_xlen == 64
// riscv64: args a0..a5, sysno a7, sp sp, retval a0
struct riscv_user_regs_proxy { unsigned long pc, ra, sp, gp, tp; unsigned long t0,t1,t2; unsigned long s0,s1; unsigned long a0,a1,a2,a3,a4,a5,a6,a7; unsigned long s2,s3,s4,s5,s6,s7,s8,s9,s10,s11; unsigned long t3,t4,t5,t6; };
typedef struct riscv_user_regs_proxy TraceRegs;
static inline int regs_read(pid_t pid, TraceRegs *r) { struct iovec iov = { .iov_base = r, .iov_len = sizeof(*r) }; return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov); }
static inline int regs_write(pid_t pid, const TraceRegs *r) { if (g_config.dry_run) return 0; struct iovec iov = { .iov_base = (void *)r, .iov_len = sizeof(*r) }; return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov); }
static inline long get_sysno(const TraceRegs *r) { return (long)r->a7; }
static inline unsigned long get_arg(const TraceRegs *r, int idx) { switch(idx){case 0:return r->a0;case 1:return r->a1;case 2:return r->a2;case 3:return r->a3;case 4:return r->a4;case 5:return r->a5;} return 0; }
static inline void set_arg(TraceRegs *r, int idx, unsigned long v) { switch(idx){case 0:r->a0=v;break;case 1:r->a1=v;break;case 2:r->a2=v;break;case 3:r->a3=v;break;case 4:r->a4=v;break;case 5:r->a5=v;break;} }
static inline unsigned long get_sp(const TraceRegs *r) { return (unsigned long)r->sp; }
static inline void set_retval(TraceRegs *r, unsigned long v) { r->a0 = v; }
static inline unsigned long get_retval(const TraceRegs *r) { return r->a0; }
#else
#error "Unsupported architecture (supported: x86_64, aarch64, riscv64)"
#endif

enum arg_reg { ARG_RDI = 0, ARG_RSI = 1, ARG_RDX = 2, ARG_R10 = 3 };

static unsigned long get_reg_by_sel(const TraceRegs *regs, enum arg_reg sel)
{
    return get_arg(regs, (int)sel);
}

static void set_reg_by_sel(TraceRegs *regs, enum arg_reg sel, unsigned long val)
{
    set_arg(regs, (int)sel, val);
}

static int write_string_on_stack(pid_t pid, TraceRegs *regs, const char *s, unsigned long *out_addr)
{
	size_t len = strlen(s) + 1;
	unsigned long rsp = get_sp(regs);
	// Keep 256B gap below RSP (beyond the 128B red zone) and align to 16 bytes
	unsigned long dest = (rsp - 512 - len);
	dest &= ~0xFUL;
	struct iovec local = { .iov_base = (void *)s, .iov_len = len };
	struct iovec remote = { .iov_base = (void *)dest, .iov_len = len };
	ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
	if (n == (ssize_t)len) { *out_addr = dest; return 0; }
	return -1;
}



static int write_two_strings_on_stack(pid_t pid, TraceRegs *regs,
                                      const char *s1, unsigned long *addr1,
                                      const char *s2, unsigned long *addr2)
{
	size_t l1 = strlen(s1) + 1;
	size_t l2 = strlen(s2) + 1;
	unsigned long rsp = get_sp(regs);
	unsigned long base = (rsp - 1024);
	// place s1 below base, then s2 below s1, align 16
	unsigned long d1 = (base - l1) & ~0xFUL;
	unsigned long d2 = (d1 - 64 - l2) & ~0xFUL;
	struct iovec lvec[2]; struct iovec rvec[2];
	lvec[0].iov_base = (void *)s1; lvec[0].iov_len = l1;
	rvec[0].iov_base = (void *)d1; rvec[0].iov_len = l1;
	lvec[1].iov_base = (void *)s2; lvec[1].iov_len = l2;
	rvec[1].iov_base = (void *)d2; rvec[1].iov_len = l2;
	ssize_t n = process_vm_writev(pid, lvec, 2, rvec, 2, 0);
	if (n < 0) return -1;
	*addr1 = d1; *addr2 = d2; return 0;
}

// Write a single string with a configurable gap below RSP
static int write_string_on_stack_with_gap(pid_t pid, TraceRegs *regs, const char *s, unsigned long gap, unsigned long *out_addr)
{
    size_t len = strlen(s) + 1;
    unsigned long rsp = get_sp(regs);
    unsigned long dest = (rsp - gap - len);
    dest &= ~0xFUL;
    struct iovec local = { .iov_base = (void *)s, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)dest, .iov_len = len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)len) { *out_addr = dest; return 0; }
    return -1;
}


static void remap_arg_path_with_stack_fallback(pid_t pid, TraceRegs *regs, enum arg_reg sel, int dirfd)
{
	unsigned long paddr = get_reg_by_sel(regs, sel);
	if (!paddr) return;
	char buf[MAX_PATH];
	if (read_string(pid, paddr, buf, sizeof buf) != 0) return;
	size_t orig_len = strlen(buf);
	if (buf[0] == '/') pm_normalize_path_inplace(buf); else resolve_relative_for_pid(buf, sizeof buf, pid, dirfd);
	if (is_excluded_prefix(buf)) { return; }
	char out[MAX_PATH];
	const char *mapped = apply_mapping(buf, out, sizeof out);
	if (mapped == buf) return;

	// Resolve symlinks with virtual directory support
	char resolved_buffer[MAX_PATH];
	if (pm_should_resolve_symlink(g_current_syscall, g_config.relsymlink)) {
		const char *final_path = pm_resolve_symlink_path_impl(buf, mapped, resolved_buffer, sizeof resolved_buffer, &g_config.mapping_config);
		if (final_path != mapped) {
			// Symlink resolution applied, use resolved path
			if (g_config.dry_run) { if (g_config.debug) fprintf(stderr, "[pathmap] dry-run: '%s' -> '%s' (symlink resolved, no write)\n", buf, final_path); return; }
			if (write_string_if_fits(pid, paddr, final_path, orig_len) == 0) {
				if (g_config.debug) fprintf(stderr, "[pathmap] in-place: '%s' -> '%s' (symlink resolved)\n", buf, final_path);
				return;
			}
			// Fallback: place on stack and retarget argument register
			unsigned long new_addr = 0;
			if (write_string_on_stack(pid, regs, final_path, &new_addr) == 0) {
				set_reg_by_sel(regs, sel, new_addr);
				if (!g_config.dry_run) ptrace(PTRACE_SETREGS, pid, NULL, regs);
				if (g_config.debug) fprintf(stderr, "[pathmap] stack: '%s' -> '%s' (symlink resolved) @0x%lx\n", buf, final_path, new_addr);
			}
			return;
		}
	}

	// No symlink resolution needed, use mapped path
	if (g_config.dry_run) { if (g_config.debug) fprintf(stderr, "[pathmap] dry-run: '%s' -> '%s' (no write)\n", buf, mapped); return; }
	if (write_string_if_fits(pid, paddr, mapped, orig_len) == 0) {
		if (g_config.debug) fprintf(stderr, "[pathmap] in-place: '%s' -> '%s'\n", buf, mapped);
		return;
	}
	// Fallback: place on stack and retarget argument register
	unsigned long new_addr = 0;
	if (write_string_on_stack(pid, regs, mapped, &new_addr) == 0) {
		set_reg_by_sel(regs, sel, new_addr);
		if (!g_config.dry_run) ptrace(PTRACE_SETREGS, pid, NULL, regs);
		if (g_config.debug) fprintf(stderr, "[pathmap] stack: '%s' -> '%s' @0x%lx\n", buf, mapped, new_addr);
	}
}

static void remap_pair_paths_with_stack(pid_t pid, TraceRegs *regs,
                                        enum arg_reg sel1, int dirfd1,
                                        enum arg_reg sel2, int dirfd2)
{
	char b1[MAX_PATH], b2[MAX_PATH];
	unsigned long a1 = get_reg_by_sel(regs, sel1);
	unsigned long a2 = get_reg_by_sel(regs, sel2);
	if (!a1 || !a2) return;
	if (read_string(pid, a1, b1, sizeof b1) != 0) return;
	if (read_string(pid, a2, b2, sizeof b2) != 0) return;
	size_t o1 = strlen(b1), o2 = strlen(b2);
	if (b1[0] == '/') pm_normalize_path_inplace(b1); else resolve_relative_for_pid(b1, sizeof b1, pid, dirfd1);
	if (b2[0] == '/') pm_normalize_path_inplace(b2); else resolve_relative_for_pid(b2, sizeof b2, pid, dirfd2);
	int ex1 = is_excluded_prefix(b1);
	int ex2 = is_excluded_prefix(b2);
	/* per-call exclude logs removed; printed once at init */
	if (ex1 && ex2) return;
	char m1[MAX_PATH], m2[MAX_PATH];
	const char *r1 = ex1 ? b1 : apply_mapping(b1, m1, sizeof m1);
	const char *r2 = ex2 ? b2 : apply_mapping(b2, m2, sizeof m2);
	if (r1 == b1 && r2 == b2) return;
	if (g_config.dry_run) { if (g_config.debug) fprintf(stderr, "[pathmap] dry-run pair: '%s'->'%s' | '%s'->'%s'\n", b1, r1, b2, r2); return; }
	int need1 = (r1 != b1);
	int need2 = (r2 != b2);
	int fit1 = 0, fit2 = 0;
	if (need1 && write_string_if_fits(pid, a1, r1, o1) == 0) { fit1 = 1; if (g_config.debug) fprintf(stderr, "[pathmap] in-place: '%s' -> '%s'\n", b1, r1); }
	if (need2 && write_string_if_fits(pid, a2, r2, o2) == 0) { fit2 = 1; if (g_config.debug) fprintf(stderr, "[pathmap] in-place: '%s' -> '%s'\n", b2, r2); }
	if ((need1 && !fit1) && (need2 && !fit2)) {
		unsigned long na1 = 0, na2 = 0;
		if (write_two_strings_on_stack(pid, regs, r1, &na1, r2, &na2) == 0) {
			set_reg_by_sel(regs, sel1, na1);
			set_reg_by_sel(regs, sel2, na2);
			if (!g_config.dry_run) ptrace(PTRACE_SETREGS, pid, NULL, regs);
			if (g_config.debug) fprintf(stderr, "[pathmap] stack-pair: '%s' -> '%s' @0x%lx | '%s' -> '%s' @0x%lx\n", b1, r1, na1, b2, r2, na2);
		}
		return;
	}
	if (need1 && !fit1) {
		unsigned long na = 0; if (write_string_on_stack(pid, regs, r1, &na) == 0) { set_reg_by_sel(regs, sel1, na); if (!g_config.dry_run) ptrace(PTRACE_SETREGS, pid, NULL, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: '%s' -> '%s' @0x%lx\n", b1, r1, na); }
	}
	if (need2 && !fit2) {
		unsigned long na = 0; if (write_string_on_stack(pid, regs, r2, &na) == 0) { set_reg_by_sel(regs, sel2, na); if (!g_config.dry_run) ptrace(PTRACE_SETREGS, pid, NULL, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: '%s' -> '%s' @0x%lx\n", b2, r2, na); }
	}
}

// Write a pointer-sized value to the tracee (used to update argv[0] pointer)
static int write_remote_ptr(pid_t pid, unsigned long addr, unsigned long value)
{
    struct iovec local = { .iov_base = &value, .iov_len = sizeof(unsigned long) };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = sizeof(unsigned long) };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)sizeof(unsigned long)) ? 0 : -1;
}

// Read a pointer-sized value from the tracee (used to read argv[0] pointer)
static int read_remote_ptr(pid_t pid, unsigned long addr, unsigned long *out_value)
{
    struct iovec local = { .iov_base = out_value, .iov_len = sizeof(unsigned long) };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = sizeof(unsigned long) };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)sizeof(unsigned long)) ? 0 : -1;
}

// Compute final mapped path, including optional symlink resolution, like fix_path()
static const char *compute_final_mapped_exec_path(const char *orig_abs, char *out, size_t out_size, int *mapped_applied)
{
    if (mapped_applied) *mapped_applied = 0;
    char mapped_buf[MAX_PATH];
    const char *mapped = apply_mapping(orig_abs, mapped_buf, sizeof mapped_buf);
    if (mapped_applied && mapped != orig_abs) *mapped_applied = 1;
    if (pm_should_resolve_symlink("exec", g_config.relsymlink)) {
        static char resolved_buffer[MAX_PATH];
        const char *final_path = pm_resolve_symlink_path_impl(orig_abs, mapped, resolved_buffer, sizeof resolved_buffer, &g_config.mapping_config);
        if (final_path != mapped) {
            strncpy(out, final_path, out_size - 1);
            out[out_size - 1] = '\0';
            return out;
        }
    }
    if (mapped != orig_abs) {
        strncpy(out, mapped, out_size - 1);
        out[out_size - 1] = '\0';
        return out;
    }
    return orig_abs;
}

static void try_update_argv0(pid_t pid, TraceRegs *regs, enum arg_reg argv_sel,
                             const char *original_path, const char *final_path)
{
    // Match LD_PRELOAD behavior: set argv[0] to mapped(argv[0]) without symlink resolution
    unsigned long argv_addr = get_reg_by_sel(regs, argv_sel);
    if (!argv_addr) return;

    // Read argv[0] pointer
    unsigned long p0_addr = 0;
    if (read_remote_ptr(pid, argv_addr, &p0_addr) != 0 || !p0_addr) return;

    char current0[MAX_PATH];
    if (read_string(pid, p0_addr, current0, sizeof current0) != 0) return;

    // Compute mapped(argv0) without symlink resolution
    char mapped0_buf[MAX_PATH];
    const char *mapped0 = pm_apply_mapping_with_config(current0, mapped0_buf, sizeof mapped0_buf, &g_config.mapping_config);
    if (!mapped0 || strcmp(mapped0, current0) == 0) return; // nothing to do

    const char *composed = mapped0;

    // Write string on stack and update argv[0] pointer
    unsigned long where = 0; if (write_string_on_stack_with_gap(pid, regs, composed, 4096, &where) != 0) return;
    if (write_remote_ptr(pid, argv_addr, where) != 0) return;

    if (g_config.debug) fprintf(stderr, "[pathmap] argv0: '%s' -> '%s' (ptr @0x%lx)\n", current0, composed, (unsigned long)argv_addr);
}

static const char *apply_mapping(const char *in, char *out, size_t out_size)
{
	const char *res = pm_apply_mapping_with_config(in, out, out_size, &g_config.mapping_config);
	if (g_config.debug && res != in) fprintf(stderr, "[pathmap] map %s: '%s' -> '%s'\n", g_current_syscall ? g_current_syscall : "", in, res);
	return res;
}


static void resolve_relative_for_pid(char *path, size_t path_size, pid_t pid, int dirfd)
{
	if (path[0] == '/') return;
	char base[MAX_PATH];
	ssize_t n = -1;
	if (dirfd == AT_FDCWD) {
		char linkp[64];
		snprintf(linkp, sizeof linkp, "/proc/%d/cwd", pid);
		n = readlink(linkp, base, sizeof base - 1);
	} else {
		char linkp[64];
		snprintf(linkp, sizeof linkp, "/proc/%d/fd/%d", pid, dirfd);
		n = readlink(linkp, base, sizeof base - 1);
	}
	if (n <= 0) return;
	base[n] = '\0';
	char tmp[MAX_PATH];
	size_t bl = strlen(base);
	size_t pl = strlen(path);
	if (bl + 1 + pl >= sizeof tmp) {
		// Truncate safely
		if (bl >= sizeof tmp - 1) bl = sizeof tmp - 1;
		memcpy(tmp, base, bl);
		if (bl < sizeof tmp - 1) tmp[bl++] = '/';
		size_t remain = (sizeof tmp - 1) - bl;
		if (pl > remain) pl = remain;
		memcpy(tmp + bl, path, pl);
		tmp[bl + pl] = '\0';
	} else {
		memcpy(tmp, base, bl);
		tmp[bl++] = '/';
		memcpy(tmp + bl, path, pl + 1);
	}
	strncpy(path, tmp, path_size - 1);
	path[path_size - 1] = '\0';
	pm_normalize_path_inplace(path);
}



static void maybe_remap_path(pid_t pid, long sysno, TraceRegs *regs)
{
	// x86_64 Linux syscall ABI
	if (sysno == SYS_open) {
		g_current_syscall = "open";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD);
		return;
	} else if (sysno == SYS_openat) {
		g_current_syscall = "openat";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0));
		return;
	} else if (sysno == SYS_newfstatat) {
		g_current_syscall = "newfstatat";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0));
		return;
	} else if (sysno == SYS_unlinkat) {
		g_current_syscall = "unlinkat";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0));
		return;
	} else if (sysno == SYS_execve) {
		g_current_syscall = "execve";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD);
		return;
	} else if (sysno == SYS_execveat) {
		g_current_syscall = "execveat";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0));
		return;
	} else if (sysno == SYS_statx) {
		g_current_syscall = "statx";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0));
		return;
	} else if (sysno == SYS_stat) {
		g_current_syscall = "stat";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD);
		return;
	} else if (sysno == SYS_lstat) {
		g_current_syscall = "lstat";
		remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD);
		return;
	} else {
		return;
	}
}




typedef struct { pid_t pid; int in_syscall; } tracee_t;
static int tracee_find_idx(tracee_t *arr, int count, pid_t p) {
	for (int i = 0; i < count; i++) if (arr[i].pid == p) return i;
	return -1;
}
static void tracee_add(tracee_t *arr, int *count, pid_t p) {
	if (*count < 1024) { arr[*count].pid = p; arr[*count].in_syscall = 0; (*count)++; }
}
static void tracee_remove(tracee_t *arr, int *count, int idx) {
	if (idx >= 0 && idx < *count) { arr[idx] = arr[*count - 1]; (*count)--; }
}

static void on_sys_enter(pid_t pid, TraceRegs *regs)
{
	long sysno = get_sysno(regs);
	g_current_syscall = NULL;
	// Common path-taking syscalls beyond open/stat/unlink/exec handled in maybe_remap_path:
	// rename/renameat/renameat2
	if (sysno == SYS_rename) {
		g_current_syscall = "rename";
		remap_pair_paths_with_stack(pid, regs, ARG_RDI, AT_FDCWD, ARG_RSI, AT_FDCWD);
		return;
	}
	if (sysno == SYS_renameat) {
		g_current_syscall = "renameat";
		remap_pair_paths_with_stack(pid, regs, ARG_RSI, (int)get_arg(regs,0), ARG_R10, (int)get_arg(regs,2));
		return;
	}
#ifdef SYS_renameat2
	if (sysno == SYS_renameat2) {
		g_current_syscall = "renameat2";
		remap_pair_paths_with_stack(pid, regs, ARG_RSI, (int)get_arg(regs,0), ARG_R10, (int)get_arg(regs,2));
		return;
	}
#endif
	// link/linkat
	if (sysno == SYS_link) {
		g_current_syscall = "link";
		remap_pair_paths_with_stack(pid, regs, ARG_RDI, AT_FDCWD, ARG_RSI, AT_FDCWD);
		return;
	}
	if (sysno == SYS_linkat) {
		g_current_syscall = "linkat";
		remap_pair_paths_with_stack(pid, regs, ARG_RSI, (int)get_arg(regs,0), ARG_R10, (int)get_arg(regs,2));
		return;
	}
	// mount_setattr/open_tree/move_mount/statmount: treat path args
#ifdef SYS_open_tree
	if (sysno == SYS_open_tree) { g_current_syscall = "open_tree"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
#ifdef SYS_move_mount
	if (sysno == SYS_move_mount) { g_current_syscall = "move_mount"; remap_pair_paths_with_stack(pid, regs, ARG_RSI, (int)get_arg(regs,0), ARG_R10, (int)get_arg(regs,2)); return; }
#endif
	// mkdir/mkdirat
	if (sysno == SYS_mkdir) { g_current_syscall = "mkdir"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_mkdirat) { g_current_syscall = "mkdirat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
	// chdir
	if (sysno == SYS_chdir) { g_current_syscall = "chdir"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	// chroot
	if (sysno == SYS_chroot) { g_current_syscall = "chroot"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	// acct
	if (sysno == SYS_acct) { g_current_syscall = "acct"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	// mkfifo/mknod and *at variants (guard missing syscalls)
#ifdef SYS_mkfifo
	if (sysno == SYS_mkfifo) { g_current_syscall = "mkfifo"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_mknod
	if (sysno == SYS_mknod) { g_current_syscall = "mknod"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_mkfifoat
	if (sysno == SYS_mkfifoat) { g_current_syscall = "mkfifoat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
#ifdef SYS_mknodat
	if (sysno == SYS_mknodat) { g_current_syscall = "mknodat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
	// chmod/chown/utimensat: path argument
	if (sysno == SYS_chmod) { g_current_syscall = "chmod"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_lchown) { g_current_syscall = "lchown"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#ifdef SYS_fchownat
	if (sysno == SYS_fchownat) { g_current_syscall = "fchownat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
	if (sysno == SYS_utimensat) { g_current_syscall = "utimensat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
	if (sysno == SYS_access) { g_current_syscall = "access"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#ifdef SYS_faccessat
	if (sysno == SYS_faccessat) { g_current_syscall = "faccessat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
	if (sysno == SYS_getxattr) { g_current_syscall = "getxattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_lgetxattr) { g_current_syscall = "lgetxattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_setxattr) { g_current_syscall = "setxattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_lsetxattr) { g_current_syscall = "lsetxattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_removexattr) { g_current_syscall = "removexattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_lremovexattr) { g_current_syscall = "lremovexattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_listxattr) { g_current_syscall = "listxattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_llistxattr) { g_current_syscall = "llistxattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_readlink) {
		g_current_syscall = "readlink";
		// const char *pathname (rdi), char *buf (rsi), size_t bufsiz (rdx)
		unsigned long paddr = get_arg(regs,0);
		char path[MAX_PATH];
		if (read_string(pid, paddr, path, sizeof path) == 0) {
			// Normalize absolute or resolve relative
			if (path[0] == '/') pm_normalize_path_inplace(path);
			else resolve_relative_for_pid(path, sizeof path, pid, AT_FDCWD);
			char out[MAX_PATH];
			const char *mapped = apply_mapping(path, out, sizeof out);
			if (mapped != path) {
				// Don't write into pathname if longer; use stack
				unsigned long new_addr = 0;
				if (write_string_if_fits(pid, paddr, mapped, strlen(path)) != 0) {
					if (write_string_on_stack(pid, regs, mapped, &new_addr) == 0) { set_arg(regs,0,new_addr); regs_write(pid, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: '%s' -> '%s' @0x%lx\n", path, mapped, new_addr); }
				}
			}
		}
		return;
	}
	if (sysno == SYS_readlinkat) {
		g_current_syscall = "readlinkat";
		// int dirfd (rdi), const char *pathname (rsi), char *buf (rdx), size_t bufsiz (r10)
		int dirfd = (int)get_arg(regs,0);
		unsigned long paddr = get_arg(regs,1);
		char path[MAX_PATH];
		if (read_string(pid, paddr, path, sizeof path) == 0) {
			resolve_relative_for_pid(path, sizeof path, pid, dirfd);
			pm_normalize_path_inplace(path);
			char out[MAX_PATH];
			const char *mapped = apply_mapping(path, out, sizeof out);
			if (mapped != path) {
				unsigned long new_addr = 0;
				if (write_string_if_fits(pid, paddr, mapped, strlen(path)) != 0) {
					if (write_string_on_stack(pid, regs, mapped, &new_addr) == 0) { set_arg(regs,1,new_addr); regs_write(pid, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: '%s' -> '%s' @0x%lx\n", path, mapped, new_addr); }
				}
			}
		}
		return;
	}
	// Handle exec argv[0] updates similar to LD_PRELOAD interposer behavior
	if (sysno == SYS_execve) {
		// filename (rdi), argv (rsi)
		unsigned long paddr = get_arg(regs,0);
		char orig_path[MAX_PATH];
		if (paddr && read_string(pid, paddr, orig_path, sizeof orig_path) == 0) {
			char raw_path[MAX_PATH];
			strncpy(raw_path, orig_path, sizeof raw_path - 1);
			raw_path[sizeof raw_path - 1] = '\0';
			// Resolve to absolute for mapping and normalization
			if (orig_path[0] == '/') pm_normalize_path_inplace(orig_path); else resolve_relative_for_pid(orig_path, sizeof orig_path, pid, AT_FDCWD);
			char final_buf[MAX_PATH];
			int mapped_applied = 0;
			const char *final_path = compute_final_mapped_exec_path(orig_path, final_buf, sizeof final_buf, &mapped_applied);
			if (mapped_applied && final_path != orig_path) {
				// ensure actual filename arg will be remapped by existing logic; just update argv[0] using RAW original like preload
				try_update_argv0(pid, regs, ARG_RSI, raw_path, final_path);
			}
		}
		// do not return here; allow existing remap handler to run below
	}
	if (sysno == SYS_execveat) {
		// (dirfd, pathname, argv, envp, flags)
		int dirfd = (int)get_arg(regs,0);
		unsigned long paddr = get_arg(regs,1);
		char orig_path[MAX_PATH];
		if (paddr && read_string(pid, paddr, orig_path, sizeof orig_path) == 0) {
			char raw_path[MAX_PATH];
			strncpy(raw_path, orig_path, sizeof raw_path - 1);
			raw_path[sizeof raw_path - 1] = '\0';
			resolve_relative_for_pid(orig_path, sizeof orig_path, pid, dirfd);
			pm_normalize_path_inplace(orig_path);
			char final_buf[MAX_PATH];
			int mapped_applied = 0;
			const char *final_path = compute_final_mapped_exec_path(orig_path, final_buf, sizeof final_buf, &mapped_applied);
			if (mapped_applied && final_path != orig_path) {
				try_update_argv0(pid, regs, ARG_RDX, raw_path, final_path);
			}
		}
		// do not return here; allow existing remap handler to run below
	}
	if (sysno == SYS_truncate) { g_current_syscall = "truncate"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#ifdef SYS_truncate64
	if (sysno == SYS_truncate64) { g_current_syscall = "truncate64"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_openat2
	if (sysno == SYS_openat2) { g_current_syscall = "openat2"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
#ifdef SYS_name_to_handle_at
if (sysno == SYS_name_to_handle_at) { g_current_syscall = "name_to_handle_at"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
#ifdef SYS_open_by_handle_at
if (sysno == SYS_open_by_handle_at) { g_current_syscall = "open_by_handle_at"; return; }
#endif
#ifdef SYS_statfs
	if (sysno == SYS_statfs) { g_current_syscall = "statfs"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_statfs64
	if (sysno == SYS_statfs64) { g_current_syscall = "statfs64"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_mount
	if (sysno == SYS_mount) {
		g_current_syscall = "mount";
		// mount(source, target, fstype, flags, data)
		remap_pair_paths_with_stack(pid, regs, ARG_RDI, AT_FDCWD, ARG_RSI, AT_FDCWD);
		return;
	}
#endif
#ifdef SYS_umount2
	if (sysno == SYS_umount2) { g_current_syscall = "umount2"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_mount_setattr
	if (sysno == SYS_mount_setattr) { g_current_syscall = "mount_setattr"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
#ifdef SYS_statmount
	if (sysno == SYS_statmount) { g_current_syscall = "statmount"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
#ifdef SYS_inotify_add_watch
	if (sysno == SYS_inotify_add_watch) { g_current_syscall = "inotify_add_watch"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, AT_FDCWD); return; }
#endif
#ifdef SYS_fanotify_mark
	if (sysno == SYS_fanotify_mark) {
		g_current_syscall = "fanotify_mark";
		// fanotify_mark(fd, flags, mask, dirfd, pathname)
		remap_arg_path_with_stack_fallback(pid, regs, ARG_R10, (int)get_arg(regs,3));
		return;
	}
#endif
#ifdef SYS_pivot_root
	if (sysno == SYS_pivot_root) {
		g_current_syscall = "pivot_root";
		remap_pair_paths_with_stack(pid, regs, ARG_RDI, AT_FDCWD, ARG_RSI, AT_FDCWD);
		return;
	}
#endif
#ifdef SYS_statvfs
	if (sysno == SYS_statvfs) { g_current_syscall = "statvfs"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_statvfs64
	if (sysno == SYS_statvfs64) { g_current_syscall = "statvfs64"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_utime
	if (sysno == SYS_utime) { g_current_syscall = "utime"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_utimes
	if (sysno == SYS_utimes) { g_current_syscall = "utimes"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_lutime
	if (sysno == SYS_lutime) { g_current_syscall = "lutime"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
#endif
#ifdef SYS_futimesat
	if (sysno == SYS_futimesat) { g_current_syscall = "futimesat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
#ifdef SYS_fchmodat
	if (sysno == SYS_fchmodat) { g_current_syscall = "fchmodat"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RSI, (int)get_arg(regs,0)); return; }
#endif
	if (sysno == SYS_chown) { g_current_syscall = "chown"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_rmdir) { g_current_syscall = "rmdir"; remap_arg_path_with_stack_fallback(pid, regs, ARG_RDI, AT_FDCWD); return; }
	if (sysno == SYS_symlink) {
		g_current_syscall = "symlink";
		// Args: const char *target (rdi), const char *linkpath (rsi)
		unsigned long taddr = get_arg(regs,0);
		unsigned long laddr = get_arg(regs,1);
		char target[MAX_PATH], linkpath[MAX_PATH];
		if (read_string(pid, taddr, target, sizeof target) == 0 &&
			read_string(pid, laddr, linkpath, sizeof linkpath) == 0) {
			// Map linkpath forward to real, and map target forward so kernel can resolve it
			// Resolve relative linkpath against CWD
			resolve_relative_for_pid(linkpath, sizeof linkpath, pid, AT_FDCWD);
			pm_normalize_path_inplace(linkpath);
			char out1[MAX_PATH], out2[MAX_PATH];
			const char *mapped_link = apply_mapping(linkpath, out1, sizeof out1);
			const char *mapped_target = apply_mapping(target, out2, sizeof out2);
			int need_link = (mapped_link != linkpath);
			int need_tgt = (mapped_target != target);
			if (need_link || need_tgt) {
				unsigned long na_link = 0, na_tgt = 0;
				if (need_link && need_tgt) {
					if (write_two_strings_on_stack(pid, regs, mapped_target, &na_tgt, mapped_link, &na_link) == 0) {
						set_arg(regs,0,na_tgt); set_arg(regs,1,na_link); regs_write(pid, regs);
						if (g_config.debug) fprintf(stderr, "[pathmap] stack-pair: target '%s' -> '%s' @0x%lx | link '%s' -> '%s' @0x%lx\n", target, mapped_target, na_tgt, linkpath, mapped_link, na_link);
					}
				} else if (need_link) {
					if (write_string_if_fits(pid, laddr, mapped_link, strlen(linkpath)) != 0) {
						if (write_string_on_stack(pid, regs, mapped_link, &na_link) == 0) { set_arg(regs,1,na_link); regs_write(pid, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: link '%s' -> '%s' @0x%lx\n", linkpath, mapped_link, na_link); }
					}
				} else if (need_tgt) {
					if (write_string_if_fits(pid, taddr, mapped_target, strlen(target)) != 0) {
						if (write_string_on_stack(pid, regs, mapped_target, &na_tgt) == 0) { set_arg(regs,0,na_tgt); regs_write(pid, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: target '%s' -> '%s' @0x%lx\n", target, mapped_target, na_tgt); }
					}
				}
			}
		}
		return;
	}
	if (sysno == SYS_symlinkat) {
		g_current_syscall = "symlinkat";
		// Args: const char *target (rdi), int newdirfd (rsi), const char *linkpath (rdx)
		unsigned long taddr = get_arg(regs,0);
		int newdirfd = (int)get_arg(regs,1);
		unsigned long laddr = get_arg(regs,2);
		char target[MAX_PATH], linkpath[MAX_PATH];
		if (read_string(pid, taddr, target, sizeof target) == 0 &&
			read_string(pid, laddr, linkpath, sizeof linkpath) == 0) {
			// Resolve linkpath relative to newdirfd, normalize, then map forward
			resolve_relative_for_pid(linkpath, sizeof linkpath, pid, newdirfd);
			pm_normalize_path_inplace(linkpath);
			char out1[MAX_PATH], out2[MAX_PATH];
			const char *mapped_link = apply_mapping(linkpath, out1, sizeof out1);
			const char *mapped_target = apply_mapping(target, out2, sizeof out2);
			int need_link = (mapped_link != linkpath);
			int need_tgt = (mapped_target != target);
			if (need_link || need_tgt) {
				unsigned long na_link = 0, na_tgt = 0;
				if (need_link && need_tgt) {
					if (write_two_strings_on_stack(pid, regs, mapped_target, &na_tgt, mapped_link, &na_link) == 0) {
						set_arg(regs,0,na_tgt); set_arg(regs,2,na_link); regs_write(pid, regs);
						if (g_config.debug) fprintf(stderr, "[pathmap] stack-pair: target '%s' -> '%s' @0x%lx | link '%s' -> '%s' @0x%lx\n", target, mapped_target, na_tgt, linkpath, mapped_link, na_link);
					}
				} else if (need_link) {
					if (write_string_if_fits(pid, laddr, mapped_link, strlen(linkpath)) != 0) {
						if (write_string_on_stack(pid, regs, mapped_link, &na_link) == 0) { set_arg(regs,2,na_link); regs_write(pid, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: link '%s' -> '%s' @0x%lx\n", linkpath, mapped_link, na_link); }
					}
				} else if (need_tgt) {
					if (write_string_if_fits(pid, taddr, mapped_target, strlen(target)) != 0) {
						if (write_string_on_stack(pid, regs, mapped_target, &na_tgt) == 0) { set_arg(regs,0,na_tgt); regs_write(pid, regs); if (g_config.debug) fprintf(stderr, "[pathmap] stack: target '%s' -> '%s' @0x%lx\n", target, mapped_target, na_tgt); }
					}
				}
			}
		}
		return;
	}
	maybe_remap_path(pid, sysno, regs);
}

int main(int argc, char **argv)
{
	const char *cli_mapping = NULL;
	const char *cli_exclude = NULL;
	static struct option longopts[] = {
		{ "debug", no_argument, 0, 'd' },
		{ "path-mapping", required_argument, 0, 'p' },
		{ "exclude", required_argument, 0, 'x' },
		{ "dry-run", no_argument, 0, 'r' },
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ 0, 0, 0, 0 }
	};
	int opt;
	while ((opt = getopt_long(argc, argv, "dp:x:rhv", longopts, NULL)) != -1) {
		switch (opt) {
			case 'd': g_config.debug = 1; break;
			case 'p': cli_mapping = optarg; break;
			case 'x': cli_exclude = optarg; break;
			case 'r': g_config.dry_run = 1; break;
			case 'h':
				fprintf(stderr, "Usage: %s [OPTIONS] <command> [args...]\n\n", argv[0]);
				fprintf(stderr, "Options:\n");
				fprintf(stderr, "  -d, --debug            Enable debug logs\n");
				fprintf(stderr, "  -p, --path-mapping M   Mapping 'FROM:TO[,FROM:TO...]' (overrides PATH_MAPPING)\n");
				fprintf(stderr, "  -x, --exclude L        Comma-separated exclude prefixes (overrides PATH_MAPPING_EXCLUDE)\n");
				fprintf(stderr, "  -r, --dry-run          Log remaps but do not modify tracee\n");
				fprintf(stderr, "  -h, --help             Show this help\n");
				fprintf(stderr, "  -v, --version          Show version\n");
				return 0;
			case 'v':
				fprintf(stderr, "pathremap %s\n", PATHMAP_VERSION);
				return 0;
			default:
				fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
				return 2;
		}
	}
	// Initialize common configuration
	pm_init_common_config(&g_config);

	// Override with CLI options if provided
	if (cli_mapping && *cli_mapping) {
		pm_load_mappings_from_env(cli_mapping, &g_config.mapping_config);
	}
	if (cli_exclude && *cli_exclude) {
		pm_load_excludes_from_env(cli_exclude, &g_config.mapping_config);
	}

	// Dry run mode is already set in the switch statement above

	if (g_config.mapping_config.mapping_count == 0 && g_config.debug) {
		fprintf(stderr, "[pathmap] PATH_MAPPING is empty; nothing to remap.\n");
	}

	if (optind >= argc) {
		fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
		return 2;
	}

	pid_t child = fork();
	if (child == -1) {
		perror("fork");
		return 1;
	}
	if (child == 0) {
		// Make child a process group leader to receive terminal signals as foreground job
		setpgid(0, 0);
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("PTRACE_TRACEME");
			_exit(1);
		}
		raise(SIGSTOP);
		execvp(argv[optind], &argv[optind]);
		perror("execvp");
		_exit(1);
	}

	int status;
	if (waitpid(child, &status, 0) == -1) {
		perror("waitpid");
		return 1;
	}
	if (ptrace(PTRACE_SETOPTIONS, child, NULL,
	           (void *)(PTRACE_O_TRACESYSGOOD |
	                    PTRACE_O_TRACEFORK |
	                    PTRACE_O_TRACEVFORK |
	                    PTRACE_O_TRACECLONE |
	                    PTRACE_O_TRACEEXEC)) == -1) {
		perror("PTRACE_SETOPTIONS");
		return 1;
	}

	// If running in a terminal, hand over foreground to the tracee's process group
	int have_tty = isatty(STDIN_FILENO);
	pid_t orig_pgrp = -1;
	if (have_tty) {
		void (*old_ttou)(int) = signal(SIGTTOU, SIG_IGN);
		void (*old_ttin)(int) = signal(SIGTTIN, SIG_IGN);
		// Ensure child is its own pgrp (in case setpgid in child raced)
		setpgid(child, child);
		orig_pgrp = tcgetpgrp(STDIN_FILENO);
		if (orig_pgrp != -1) tcsetpgrp(STDIN_FILENO, child);
		signal(SIGTTOU, old_ttou);
		signal(SIGTTIN, old_ttin);
	}

	// Track multiple tracees (fork/clone/exec)
	tracee_t tracees[1024];
	int tracee_count = 0;
	tracee_add(tracees, &tracee_count, child);

	// Kick off the initial child
	if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
		perror("PTRACE_SYSCALL");
		return 1;
	}

	// Ensure we free any malloc'ed strings on exit
	atexit(cleanup_config);

	while (tracee_count > 0) {
		pid_t pid = waitpid(-1, &status, __WALL);
		if (pid == -1) {
			if (errno == EINTR) continue;
			if (errno == ECHILD) break;
			perror("waitpid");
			break;
		}
		int idx = tracee_find_idx(tracees, tracee_count, pid);
		if (WIFEXITED(status) || WIFSIGNALED(status)) { if (idx >= 0) tracee_remove(tracees, &tracee_count, idx); if (tracee_count == 0 && have_tty && orig_pgrp != -1) { void (*old_ttou)(int) = signal(SIGTTOU, SIG_IGN); void (*old_ttin)(int) = signal(SIGTTIN, SIG_IGN); tcsetpgrp(STDIN_FILENO, orig_pgrp); signal(SIGTTOU, old_ttou); signal(SIGTTIN, old_ttin); } continue; }
		if (!WIFSTOPPED(status)) { goto resume; }

		int sig = WSTOPSIG(status);
		int deliver_sig = 0; /* always initialized */
		// Handle PTRACE events (fork/clone/exec)
		if (sig == SIGTRAP) {
			unsigned int event = (unsigned int)status >> 16;
			if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_EXEC) {
				unsigned long newpid = 0;
				if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &newpid) == 0) {
					if (event != PTRACE_EVENT_EXEC) {
						pid_t cpid = (pid_t)newpid;
						tracee_add(tracees, &tracee_count, cpid);
						// Apply same options and continue
						ptrace(PTRACE_SETOPTIONS, cpid, NULL,
						       (void *)(PTRACE_O_TRACESYSGOOD |
						                PTRACE_O_TRACEFORK |
						                PTRACE_O_TRACEVFORK |
						                PTRACE_O_TRACECLONE |
						                PTRACE_O_TRACEEXEC));
						ptrace(PTRACE_SYSCALL, cpid, NULL, NULL);
					}
				}
				goto resume;
			}
		}

		// Syscall-stop?
		if (sig & 0x80) {
			if (idx < 0) { goto resume; }
			tracees[idx].in_syscall ^= 1;
			TraceRegs regs;
			if (regs_read(pid, &regs) == -1) { goto resume; }
			if (tracees[idx].in_syscall) on_sys_enter(pid, &regs);
			// regs may have been updated on exit; no need to set unless changed inside handlers
		}
		else {
			// Regular signal-stop (e.g., SIGINT, SIGTSTP, SIGWINCH). Re-inject to tracee.
			if (sig != SIGTRAP && sig != SIGSTOP) {
				deliver_sig = sig;
			}
		}

	resume:
		if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)deliver_sig) == -1) {
			if (errno != ESRCH) perror("PTRACE_SYSCALL");
		}
	}
	return 0;
}


