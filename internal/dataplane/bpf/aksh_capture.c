//go:build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aksh_capture.c - the Aksh phase 5A capture layer, kernel side.
 *
 * Six cgroup-attached BPF programs and three maps, per design
 * docs/design/S1a-dataplane-capture.md section 6.
 *
 *   aksh_connect4      cgroup/connect4    redirect TCP egress to the listener
 *   aksh_sockops       sockops            re-key the record by source pair
 *   aksh_sock_create   cgroup/sock_create deny egress sockets other than TCP
 *                                         stream and UDP datagram
 *   aksh_sendmsg4      cgroup/sendmsg4    deny UDP egress except the DNS exception
 *   aksh_connect6_deny cgroup/connect6    deny IPv6 TCP egress (ADR-S1a-04)
 *   aksh_sendmsg6      cgroup/sendmsg6    deny IPv6 UDP egress
 *
 * THIS FILE CONTAINS NO POLICY LITERALS.  There is no proxy UID, no listener
 * address, no listener port and no DNS address anywhere below.  All of them are
 * written by the Go loader into the aksh_config map before the programs are
 * attached, and the map is then frozen (ADR-S1a-06, design 6.4.4, 6.8.2 step 5).
 * The proof-of-concept's `#define PROXY_UID 1337` in C plus `const proxyUID` in
 * Go is exactly the defect this removes: divergence between the two was a silent
 * capture loop or a silent capture bypass, and no compiler could catch it.
 *
 * Return-value convention, which differs by program type:
 *   cgroup/{connect4,connect6,sendmsg4,sendmsg6}  1 = allow, 0 = fail the
 *       syscall with EPERM.
 *   cgroup/sock_create                            1 = allow, 0 = fail socket()
 *       with EPERM.
 *   sockops                                       the return value is not a
 *       verdict; 0 is the conventional "nothing to say".
 */

#include "aksh_bpf_helpers.h"

/* ------------------------------------------------------------------ *
 * Map value and key layouts.  Design 6.4.1.  Every hole is explicit,
 * because an implicit hole is a C/Go ABI break waiting to happen and the
 * Go loader compares aksh_config byte-for-byte on read-back (gate P10).
 * ------------------------------------------------------------------ */

/* Value of both destination maps - 24 bytes. */
struct orig_dst {
	__u32 ip;       /* offset  0  network byte order                    */
	__u16 port;     /* offset  4  network byte order                    */
	__u16 flags;    /* offset  6  bit0 DST_IPV4, bit1 DST_IPV6 reserved */
	__u32 uid;      /* offset  8  host order, real uid that connect()ed */
	__u32 pad;      /* offset 12  must be zero                          */
	__u64 stamp_ns; /* offset 16  bpf_ktime_get_ns() at connect4        */
};

/* Key of pair_orig_dst - 8 bytes, no padding on any ABI. */
struct pair_key {
	__u32 ip;   /* offset 0  network byte order                          */
	__u32 port; /* offset 4  HOST byte order, __u32 because that is the   */
		    /*           width of bpf_sock_ops.local_port            */
};

/*
 * Value of aksh_config - 32 bytes, all padding explicit.
 *
 * Design 6.4.1 names this struct `aksh_config`, the same identifier as the map.
 * C allows that (tags and object names are separate namespaces) but bpf2go does
 * not: BTF holds both a Struct and a Var under that name and `-type aksh_config`
 * fails with "found multiple types".  The map name is externally significant -
 * it is the kernel's map name and the key into CollectionSpec.Maps - so the
 * struct tag is what changed.  See the Findings document.
 */
struct aksh_cfg {
	__u32 proxy_uid;     /* offset  0  host order                      */
	__u32 listener_ip4;  /* offset  4  network order                   */
	__u16 listener_port; /* offset  8  network order                   */
	__u16 flags;         /* offset 10  host order                      */
	__u32 dns_ip4;       /* offset 12  network order, 0 = disabled     */
	__u16 dns_port;      /* offset 16  network order, as listener_port */
	__u16 pad;           /* offset 18  must be zero                    */
	__u32 pad2;          /* offset 20  must be zero                    */
	__u64 reserved;      /* offset 24  8-byte aligned                  */
};

/* orig_dst.flags */
#define DST_IPV4 (1 << 0)
#define DST_IPV6 (1 << 1) /* reserved; 5A never sets it */

/* aksh_config.flags */
#define FLAG_CAPTURE_ENABLED (1 << 0)
#define FLAG_BLOCK_NON_TCP (1 << 1)
#define FLAG_DENY_IPV6 (1 << 2)

/* ------------------------------------------------------------------ *
 * Maps.  Design 6.4.2.
 *
 * max_entries below are the design's defaults (13.1).  The Go loader
 * overrides them on the CollectionSpec before NewCollection, so sizing is
 * configurable without regenerating this object (design 6.4.4).
 * ------------------------------------------------------------------ */

/*
 * The socket cookie is the only stable key available between connect() and the
 * assignment of a source port.  LRU rather than HASH because an entry whose
 * connection is abandoned before ESTABLISHED is cleaned up by nothing else;
 * eviction of a live entry degrades to a T1 close, which is fail-closed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct orig_dst);
} cookie_orig_dst SEC(".maps");

/*
 * Userspace cannot read the client's socket cookie, but accept() gives it the
 * peer (ip, port) pair.  sock_ops re-keys the record into this map at
 * ACTIVE_ESTABLISHED, which the TCP state machine guarantees happens strictly
 * before the listener can accept() the connection (design 6.3).
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct pair_key);
	__type(value, struct orig_dst);
} pair_orig_dst SEC(".maps");

/*
 * Written once by the loader before attach, then frozen with BPF_MAP_FREEZE so
 * that a compromised proxy holding CAP_BPF cannot clear FLAG_CAPTURE_ENABLED
 * and turn capture off from inside its own address space (design 6.4.2).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct aksh_cfg);
} aksh_config SEC(".maps");

/*
 * Capture bypass prefixes.  A destination that matches one of these is left
 * alone: not redirected, and therefore not policed.  It exists because a real
 * agent pod must reach its own in-cluster control plane over plaintext (its
 * scheduler, a local tool server, a metrics endpoint), and aksh's job is to
 * police egress to EXTERNAL services, not to broker the pod's calls to the
 * cluster it runs in.  Without this every such connection is redirected, found
 * to be plaintext, and rejected T9.
 *
 * This is a deliberate hole, so it is held to the same discipline as the config
 * map: the loader writes it before attach and then freezes it, so a compromised
 * proxy holding CAP_BPF cannot widen its own bypass to 0.0.0.0/0 and switch
 * capture off.  Userspace is what refuses an over-broad prefix; the kernel side
 * only has to be honest about matching.
 *
 * Empty is the default and means "bypass nothing", which is exactly the
 * behaviour that existed before this map.
 */
struct bypass_key {
	__u32 prefixlen; /* offset 0  HOST order, bits, 0..32  */
	__u32 addr;      /* offset 4  NETWORK order            */
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct bypass_key);
	__type(value, __u8);
} bypass_cidr4 SEC(".maps");

/*
 * True when dst (network order) falls inside a configured bypass prefix.
 *
 * LPM_TRIE takes the key's prefixlen as "match at least this many bits", so a
 * full 32-bit lookup finds the longest configured prefix covering the address.
 * A lookup failure is not an error condition here: it is the ordinary "no
 * bypass configured for this destination" answer, and the fail-closed direction
 * is to capture, which is what returning 0 does.
 */
static __always_inline int aksh_bypassed4(__u32 dst)
{
	struct bypass_key k;

	k.prefixlen = 32;
	k.addr = dst;

	return bpf_map_lookup_elem(&bypass_cidr4, &k) != 0;
}

static __always_inline struct aksh_cfg *aksh_cfg_get(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&aksh_config, &key);
}

static __always_inline __u32 aksh_uid(void)
{
	return (__u32)(bpf_get_current_uid_gid() & 0xffffffff);
}

/* ------------------------------------------------------------------ *
 * connect4.  Design 6.2.
 * ------------------------------------------------------------------ */

SEC("cgroup/connect4")
int aksh_connect4(struct bpf_sock_addr *ctx)
{
	struct aksh_cfg *cfg;
	struct orig_dst v = {};
	__u64 cookie;
	__u32 uid;
	__u32 dst;

	/*
	 * A missing config means the loader is mid-init.  The loader writes and
	 * freezes the config BEFORE attach, so this branch is unreachable in
	 * practice; it exists because the verifier requires the NULL check.
	 */
	cfg = aksh_cfg_get();
	if (!cfg)
		return 1;

	/*
	 * Loop prevention (design 6.5).  bpf_get_current_uid_gid() returns the
	 * REAL uid, which a process that has dropped privileges cannot change
	 * back, unlike the effective uid.  Computed up front because both the
	 * non-TCP branch below and the TCP path need it.
	 */
	uid = aksh_uid();

	/*
	 * UDP connect() also reaches this hook (udp_prot.pre_connect calls
	 * BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK), but a UDP socket that is
	 * subsequently connect()ed becomes invisible to cgroup/sendmsg4 for
	 * the rest of its life: udp_sendmsg's CGROUP_UDP4_SENDMSG hook only
	 * fires while the socket is unconnected (msg->msg_name != NULL). An
	 * unconditional allow here would therefore let a non-proxy UID turn
	 * one connect() into a permanent, unfiltered UDP egress channel. That
	 * is not hypothetical any more: sock_create now permits UDP datagram
	 * sockets so the DNS carve-out below is reachable, so this gate is the
	 * only thing bounding a connected UDP socket. Apply sendmsg4's own rule
	 * here instead of an unconditional allow, so a connected UDP socket is
	 * held to the same destination check that send-time would apply.
	 */
	if (ctx->protocol != IPPROTO_TCP) {
		if ((cfg->flags & FLAG_BLOCK_NON_TCP) == 0)
			return 1;

		if (uid == cfg->proxy_uid)
			return 1;

		if (cfg->dns_ip4 != 0 && ctx->user_ip4 == cfg->dns_ip4 &&
		    ctx->user_port == cfg->dns_port)
			return 1;

		return 0;
	}

	if ((cfg->flags & FLAG_CAPTURE_ENABLED) == 0)
		return 1;

	if (uid == cfg->proxy_uid)
		return 1;

	/* 127.0.0.0/8 is never redirected.  Endian-independent by construction. */
	dst = ctx->user_ip4;
	if ((bpf_ntohl(dst) >> 24) == 127)
		return 1;

	/*
	 * DEV-01, the single INV-3 exception.  Both operands hold network-order
	 * bytes, so this is a plain comparison with no byte swap (design 6.4.3).
	 */
	if (cfg->dns_ip4 != 0 && dst == cfg->dns_ip4 &&
	    ctx->user_port == cfg->dns_port)
		return 1;

	/*
	 * Configured bypass prefixes.  Checked after the DNS carve-out because
	 * that one is a single exact destination and cheaper, and before the
	 * redirect because the whole point is not to redirect.  Unlike the DNS
	 * exception this is port-independent: the in-cluster control plane a
	 * pod must reach does not sit on one well-known port, and a port is not
	 * a security boundary anyway.
	 */
	if (aksh_bypassed4(dst))
		return 1;

	cookie = bpf_get_socket_cookie(ctx);
	v.ip = dst;
	v.port = (__u16)ctx->user_port;
	v.flags = DST_IPV4;
	v.uid = uid;
	v.pad = 0;
	v.stamp_ns = bpf_ktime_get_ns();

	/*
	 * FAIL CLOSED.  If the destination cannot be recorded we must not
	 * redirect: the listener could not recover it and would close with T1
	 * anyway, so EPERM at connect() gives the agent a truthful error rather
	 * than a confusing reset.
	 */
	if (bpf_map_update_elem(&cookie_orig_dst, &cookie, &v, BPF_ANY) != 0)
		return 0;

	ctx->user_ip4 = cfg->listener_ip4;
	ctx->user_port = cfg->listener_port;

	return 1;
}

/* ------------------------------------------------------------------ *
 * sock_ops.  Design 6.3.
 * ------------------------------------------------------------------ */

SEC("sockops")
int aksh_sockops(struct bpf_sock_ops *skops)
{
	struct pair_key k = {};
	struct orig_dst *v;
	__u64 cookie;

	if (skops->family != AF_INET)
		return 0;

	/*
	 * The source port is not stable until the socket is bound, which for an
	 * unbound connecting socket happens inside connect().  TCP_CONNECT_CB is
	 * too early; ACTIVE_ESTABLISHED fires when the client processes the
	 * SYN-ACK, strictly before the server side can accept().
	 */
	if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
		return 0;

	cookie = bpf_get_socket_cookie(skops);
	v = bpf_map_lookup_elem(&cookie_orig_dst, &cookie);
	if (!v)
		return 0; /* not one of ours */

	k.ip = skops->local_ip4;   /* network byte order */
	k.port = skops->local_port; /* HOST byte order - see design 6.4.3 */

	/*
	 * BPF_ANY so that a reused (ip, port) tuple overwrites rather than
	 * fails.  Combined with delete-on-lookup in userspace, a stale record
	 * cannot be inherited by a later connection.
	 */
	bpf_map_update_elem(&pair_orig_dst, &k, v, BPF_ANY);
	bpf_map_delete_elem(&cookie_orig_dst, &cookie);

	return 0;
}

/* ------------------------------------------------------------------ *
 * Non-TCP and IPv6 denial.  Design 6.9.
 *
 * These four replace the iptables filter/OUTPUT rule that S1 used to close
 * INV-3's protocol axis (S7 B4).  Unlike connect4, a missing config here is
 * treated as DENY: these programs exist to close a bypass, and the config is
 * written and frozen before attach, so the branch is unreachable in the same
 * way connect4's is.  See the Findings document for why the two directions
 * differ.
 * ------------------------------------------------------------------ */

SEC("cgroup/sock_create")
int aksh_sock_create(struct bpf_sock *ctx)
{
	struct aksh_cfg *cfg;

	cfg = aksh_cfg_get();
	if (!cfg)
		return 0;

	if ((cfg->flags & FLAG_BLOCK_NON_TCP) == 0)
		return 1;

	if (aksh_uid() == cfg->proxy_uid)
		return 1;

	/*
	 * Plain TCP stream sockets.  Checking ctx->type alone is not
	 * sufficient: socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) also has
	 * sk_type == SOCK_STREAM, and SCTP never reaches cgroup/connect4 or
	 * cgroup/connect6 (sctp_prot installs no .pre_connect and its
	 * proto_ops.connect bypasses __inet_stream_connect entirely), so an
	 * SCTP stream socket that passed a type-only check would be an
	 * unmediated, unredirected egress channel identical in effect to the
	 * SOCK_RAW/SOCK_SEQPACKET cases this program exists to block.
	 * Requiring protocol == IPPROTO_TCP closes that hole; ordinary
	 * socket(AF_INET, SOCK_STREAM, 0) is unaffected because inet_create()
	 * normalises protocol 0 to IPPROTO_TCP before this hook runs.
	 */
	if (ctx->type == SOCK_STREAM && ctx->protocol == IPPROTO_TCP)
		return 1;

	/*
	 * DEV-01, socket-creation half.  cgroup/sock_create cannot scope a UDP
	 * socket to the DNS server on its own: struct bpf_sock describes the
	 * socket, not a destination, and an unconnected datagram socket has no
	 * destination yet.  Denying SOCK_DGRAM outright therefore made the
	 * address-and-port-scoped carve-out in connect4 and sendmsg4 unreachable
	 * code -- the workload could never create the socket that would reach
	 * those hooks -- so dns_ip4/dns_port had no effect and a captured
	 * workload could not resolve a name at all.  The file's own comment at
	 * connect4 anticipated this ("if that block is ever relaxed for a DNS
	 * carve-out"); this is that relaxation.
	 *
	 * Permit UDP datagram sockets and let connect4 and sendmsg4 decide where
	 * they may send.  Reachable egress is unchanged by this: both hooks
	 * still allow exactly one destination, cfg->dns_ip4 on cfg->dns_port,
	 * and when no DNS server is configured (dns_ip4 == 0) both deny every
	 * datagram, so the socket can be created but can reach nothing.  What
	 * changes is only which syscall reports the denial -- sendto/connect
	 * with EPERM rather than socket() with EPERM.
	 *
	 * protocol == IPPROTO_UDP is required for the same reason IPPROTO_TCP is
	 * above.  It excludes SOCK_DGRAM sockets of other protocols that do not
	 * pass through cgroup/sendmsg4, in particular the IPPROTO_ICMP "ping"
	 * sockets permitted by net.ipv4.ping_group_range.  socket(AF_INET,
	 * SOCK_DGRAM, 0) is unaffected: inet_create() normalises protocol 0 to
	 * IPPROTO_UDP before this hook runs.
	 */
	if (ctx->type == SOCK_DGRAM && ctx->protocol == IPPROTO_UDP)
		return 1;

	return 0;
}

SEC("cgroup/sendmsg4")
int aksh_sendmsg4(struct bpf_sock_addr *ctx)
{
	struct aksh_cfg *cfg;

	cfg = aksh_cfg_get();
	if (!cfg)
		return 0;

	if ((cfg->flags & FLAG_BLOCK_NON_TCP) == 0)
		return 1;

	if (aksh_uid() == cfg->proxy_uid)
		return 1;

	/* DEV-01: one address, one port, from the config map. */
	if (cfg->dns_ip4 != 0 && ctx->user_ip4 == cfg->dns_ip4 &&
	    ctx->user_port == cfg->dns_port)
		return 1;

	return 0;
}

SEC("cgroup/connect6")
int aksh_connect6_deny(struct bpf_sock_addr *ctx)
{
	struct aksh_cfg *cfg;

	cfg = aksh_cfg_get();
	if (!cfg)
		return 0;

	if ((cfg->flags & FLAG_DENY_IPV6) == 0)
		return 1;

	if (aksh_uid() == cfg->proxy_uid)
		return 1;

	/*
	 * EPERM at connect() rather than a silent drop: getaddrinfo returns both
	 * families, Happy Eyeballs tries IPv6 first, gets an immediate error and
	 * falls back to IPv4 within milliseconds.  A drop would stall every
	 * connection for seconds.
	 */
	return 0;
}

SEC("cgroup/sendmsg6")
int aksh_sendmsg6(struct bpf_sock_addr *ctx)
{
	struct aksh_cfg *cfg;

	cfg = aksh_cfg_get();
	if (!cfg)
		return 0;

	if ((cfg->flags & FLAG_BLOCK_NON_TCP) == 0 &&
	    (cfg->flags & FLAG_DENY_IPV6) == 0)
		return 1;

	if (aksh_uid() == cfg->proxy_uid)
		return 1;

	return 0;
}

char _license[] SEC("license") = "GPL";
