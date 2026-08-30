/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) */
/*
 * aksh_bpf_helpers.h - the minimal subset of libbpf's <bpf/bpf_helpers.h> and
 * <bpf/bpf_endian.h> that internal/dataplane/bpf/aksh_capture.c requires.
 *
 * Vendored for the reason given in aksh_uapi_bpf.h and ADR-S1a-05: the object
 * committed to the repository must be reproducible from the pinned clang alone,
 * with no dependency on the libbpf version installed on the build host.
 *
 * The helper function-pointer declarations below carry the kernel's stable
 * helper IDs.  An ID is ABI: changing a number here calls a different helper.
 * The IDs were taken from /usr/include/bpf/bpf_helper_defs.h (libbpf) and are
 * the same numbers listed in the kernel's enum bpf_func_id.
 */

#ifndef AKSH_BPF_HELPERS_H
#define AKSH_BPF_HELPERS_H

#include "aksh_uapi_bpf.h"

/* Section attribute.  `used` keeps the symbol through -O2 dead-code removal. */
#define SEC(name) __attribute__((section(name), used))

/*
 * BPF has no call frame for these helpers on 5.15 for every program type, and
 * inlining keeps the verifier's job simple; libbpf defines the same macro.
 */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* BTF-defined map declaration macros, as in libbpf's bpf_helpers.h. */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* Helpers.  IDs from enum bpf_func_id; see the file comment. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				   __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)46;

/*
 * Byte-order helpers, as in libbpf's bpf_endian.h.  __builtin_bswap is a
 * compile-time constant fold for constant arguments and a single BPF byte-swap
 * instruction otherwise.
 */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#define bpf_ntohl(x) (x)
#define bpf_htonl(x) (x)
#else
#error "byte order not determined by the compiler"
#endif

#endif /* AKSH_BPF_HELPERS_H */
