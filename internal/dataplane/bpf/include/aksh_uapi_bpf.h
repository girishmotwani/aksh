/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) */
/*
 * aksh_uapi_bpf.h - the minimal subset of Linux UAPI <linux/bpf.h> that
 * internal/dataplane/bpf/aksh_capture.c requires.
 *
 * The struct and enum definitions below are copied verbatim (comments trimmed)
 * from the Linux kernel UAPI header linux/bpf.h, which is dual licensed under
 * GPL-2.0 WITH Linux-syscall-note precisely so that userspace and BPF programs
 * may include it.  They are reproduced here rather than included from the build
 * host so that the committed object (ADR-S1a-05) depends on the pinned clang
 * version and nothing else: no kernel headers, no vmlinux.h, no BTF from the
 * build host, and therefore no CO-RE relocations.
 *
 * Field ORDER and field WIDTH in these structs are ABI.  The kernel's context
 * rewriter translates an access at offset N into a load from the real socket
 * structure, so a struct whose layout differs from the kernel's reads the wrong
 * field with no diagnostic.  Do not reorder, do not narrow, do not "tidy".
 * Fields past the ones this program uses are retained for exactly that reason.
 */

#ifndef AKSH_UAPI_BPF_H
#define AKSH_UAPI_BPF_H

/* Fixed-width types.  Defined here so that <linux/types.h> is not required. */
typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;

/* From <linux/in.h>. */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* From <bits/socket_type.h> / <linux/net.h>. */
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOCK_SEQPACKET 5

/* From <linux/socket.h>. */
#define AF_INET 2
#define AF_INET6 10

/* From <linux/bpf.h>: BPF_MAP_TYPE_* (only the three this program declares). */
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LPM_TRIE 11

/* From <linux/bpf.h>: map creation flags.  LPM_TRIE accepts no other mode. */
#define BPF_F_NO_PREALLOC (1U << 0)

/* From <linux/bpf.h>: flags for bpf_map_update_elem(). */
#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

/* From <linux/bpf.h>. */
#define __bpf_md_ptr(type, name) \
	union {                  \
		type name;       \
		__u64 : 64;      \
	} __attribute__((aligned(8)))

/*
 * From <linux/bpf.h>.  Context of BPF_PROG_TYPE_CGROUP_SOCK_ADDR programs
 * (connect4, connect6, sendmsg4, sendmsg6).
 *
 * user_port is a __u32 whose low 16 bits hold the port as network-order bytes;
 * the kernel zero-extends a 2-byte load into it, so the upper 16 bits are
 * always zero.  See design section 6.4.3.
 */
struct bpf_sock_addr {
	__u32 user_family;   /* read only */
	__u32 user_ip4;      /* network byte order, read/write */
	__u32 user_ip6[4];   /* network byte order, read/write */
	__u32 user_port;     /* network byte order, read/write */
	__u32 family;        /* read only */
	__u32 type;          /* read only */
	__u32 protocol;      /* read only */
	__u32 msg_src_ip4;   /* network byte order, read/write */
	__u32 msg_src_ip6[4];/* network byte order, read/write */
	__bpf_md_ptr(struct bpf_sock *, sk);
};

/*
 * From <linux/bpf.h>.  Context of BPF_PROG_TYPE_CGROUP_SOCK programs
 * (sock_create), and the `sk` member of the two contexts above.
 */
struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;   /* host byte order */
	__be16 dst_port;  /* network byte order */
	__u16 : 16;       /* zero padding */
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

/*
 * From <linux/bpf.h>.  Context of BPF_PROG_TYPE_SOCK_OPS programs.
 *
 * Note local_port: host byte order, unlike every neighbouring field.  That
 * asymmetry is the kernel's, and design section 6.4.3 preserves it deliberately
 * rather than normalising it.
 */
struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;    /* network byte order */
	__u32 local_ip4;     /* network byte order */
	__u32 remote_ip6[4]; /* network byte order */
	__u32 local_ip6[4];  /* network byte order */
	__u32 remote_port;   /* network byte order */
	__u32 local_port;    /* HOST byte order */
	__u32 is_fullsock;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__bpf_md_ptr(void *, skb_data);
	__bpf_md_ptr(void *, skb_data_end);
	__u32 skb_len;
	__u32 skb_tcp_flags;
	__u64 skb_hwtstamp;
};

/* From <linux/bpf.h>: sock_ops operators.  Only the one this program uses. */
#define BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB 4

#endif /* AKSH_UAPI_BPF_H */
