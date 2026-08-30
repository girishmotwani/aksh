//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// Resolver-construction sentinels named by the unit test specification
// (§10, rows #119-120). They are declared in the Linux file because the
// resolver only exists on Linux; the non-Linux stub returns
// ErrUnsupportedPlatform before any of these can be reached.
//
// Resolution failures reuse the frozen package taxonomy in errors.go rather
// than introducing a parallel sentinel: every benign rejection wraps
// ErrNoOriginalDestination (the T1 umbrella of design §14) so a consumer's
// errors.Is(err, ErrNoOriginalDestination) classifies them uniformly, while
// stale and malformed records additionally wrap ErrStaleEntry / ErrMalformedEntry
// (via errors.Join) so the specific cause survives for diagnostics.
var (
	// ErrMissingMap is returned when the pair destination map is nil (#119).
	ErrMissingMap = errors.New("capture: pair destination map is nil")
	// ErrInvalidMaxAge is returned when the freshness bound is not positive (#120).
	ErrInvalidMaxAge = errors.New("capture: maxAge must be positive")
)

// Compile-time proof that the Linux implementation satisfies the frozen
// dataplane.DestinationResolver interface (design §8).
var _ dataplane.DestinationResolver = (*BPFDestinationResolver)(nil)

// BPFDestinationResolver recovers the pre-redirect destination of an accepted
// connection from the pair_orig_dst BPF map. It holds no per-connection state
// and is safe for concurrent use: cilium/ebpf map operations are individual
// bpf() syscalls and LookupAndDelete is atomic in the kernel, so two goroutines
// can never both consume the same entry (design §16).
type BPFDestinationResolver struct {
	pairMap  *ebpf.Map             // pair_orig_dst
	proxyUID uint32                // the excluded proxy uid; a match is a loop (T2)
	maxAge   time.Duration         // freshness bound; entries older than this are stale
	now      func() uint64         // CLOCK_MONOTONIC nanoseconds; injectable for tests
	metrics  audit.MetricsRecorder // records quiet T1 and alerting T2 rejections
}

// NewBPFDestinationResolver constructs a resolver from the pair_orig_dst map and
// the capture options. destMap is typed as any so the platform-neutral slice of
// this package adds no module dependency; here it is asserted to the concrete
// *ebpf.Map. A nil map, a non-positive maxAge or a nil metrics recorder are
// rejected before the resolver is returned (#119-#122).
func NewBPFDestinationResolver(destMap any, opts Options) (*BPFDestinationResolver, error) {
	pairMap, _ := destMap.(*ebpf.Map)
	if pairMap == nil {
		return nil, ErrMissingMap
	}
	if opts.DestMaxAge <= 0 {
		return nil, ErrInvalidMaxAge
	}
	if opts.Metrics == nil {
		return nil, ErrMissingMetrics
	}
	return &BPFDestinationResolver{
		pairMap:  pairMap,
		proxyUID: opts.ProxyUID,
		maxAge:   opts.DestMaxAge,
		now:      monotonicNowNS,
		metrics:  opts.Metrics,
	}, nil
}

// Resolve recovers the original destination of conn from the pair map. Every
// error is terminal for the connection; none is retried and none is substituted
// with a guess (INV-8). The steps follow design §8.1.
func (r *BPFDestinationResolver) Resolve(conn net.Conn) (netip.AddrPort, error) {
	if r == nil {
		return netip.AddrPort{}, ErrMissingResolver
	}
	if conn == nil {
		return netip.AddrPort{}, fmt.Errorf("%w: nil connection", ErrNoOriginalDestination)
	}

	// 1. The peer must be a TCP address.
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: peer is not a TCP address", ErrNoOriginalDestination)
	}

	// 2. IPv6 is denied in 5A; the peer must be IPv4.
	peer := tcpAddr.AddrPort()
	peerAddr := peer.Addr().Unmap()
	if !peerAddr.Is4() {
		return netip.AddrPort{}, fmt.Errorf("%w: peer is not IPv4", ErrNoOriginalDestination)
	}

	// 3. Build the lookup key. The address word holds the four address bytes in
	//    network order reinterpreted as a native word; the port is the host-order
	//    local_port zero-extended into a __u32 (design §6.4.1).
	a4 := peerAddr.As4()
	key := akshPairKey{IP: binary.NativeEndian.Uint32(a4[:]), Port: uint32(peer.Port())}

	// 4. Consume the entry: LookupAndDelete, not Lookup, so a stale record can
	//    never be replayed by a later non-redirected connection (design §8.1, INV-3).
	var val akshPairValue
	if err := r.pairMap.LookupAndDelete(&key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return netip.AddrPort{}, fmt.Errorf("%w: pair map miss", ErrNoOriginalDestination)
		}
		return netip.AddrPort{}, fmt.Errorf("%w: %w", ErrMapUnavailable, err)
	}

	// 5. Loop guard (T2): the recovered record was written for a connection made
	//    by the proxy uid, so the UID exclusion or the config map failed. This is
	//    the one alerting rejection the resolver can attest.
	if val.UID == r.proxyUID {
		r.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonLoopGuard, audit.TransportTLS, true)
		return netip.AddrPort{}, ErrLoopGuard
	}

	// 6. Freshness. The BPF stamp is CLOCK_MONOTONIC and must not exceed now();
	//    a stamp in the future is a clock/record anomaly and is rejected as
	//    malformed rather than silently treated as fresh. Otherwise an entry
	//    older than maxAge is stale.
	now := r.now()
	if val.StampNS > now {
		return netip.AddrPort{}, fmt.Errorf("%w: record stamp is in the future",
			errors.Join(ErrMalformedEntry, ErrNoOriginalDestination))
	}
	if now-val.StampNS > uint64(r.maxAge.Nanoseconds()) {
		return netip.AddrPort{}, fmt.Errorf("record older than %s: %w", r.maxAge,
			errors.Join(ErrStaleEntry, ErrNoOriginalDestination))
	}

	// 7. The value must be marked IPv4.
	if val.Flags&dstIPv4 == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: value not marked IPv4",
			errors.Join(ErrMalformedEntry, ErrNoOriginalDestination))
	}

	// 8. Decode the destination. The address word is network-order bytes; the
	//    port is network-order bytes converted to a host-order integer.
	var ip [4]byte
	binary.NativeEndian.PutUint32(ip[:], val.IP)
	dst := netip.AddrPortFrom(netip.AddrFrom4(ip), ntohs(val.Port))

	// 8a. A pod-local (loopback) destination must never appear in the pair map,
	//     because connect4 does not redirect 127.0.0.0/8 (design §6.2). When one
	//     does it is a benign anomaly - the pod dialling its own address - and is
	//     rejected as a quiet T1 with reason=pod_local, recorded but never alerted
	//     (design §14 T1 pod-local case). Pod-local classification for real, live
	//     addresses is the listener's job via its pod-local address set (§16); the
	//     resolver only rejects the impossible-in-production loopback record here.
	if dst.Addr().IsLoopback() {
		r.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonPodLocalDestination, audit.TransportTLS, false)
		return netip.AddrPort{}, fmt.Errorf("%w: pod-local destination", ErrNoOriginalDestination)
	}

	// 9. Reject a corrupt record defensively rather than trusting it.
	if !dst.IsValid() || dst.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: decoded destination is invalid",
			errors.Join(ErrMalformedEntry, ErrNoOriginalDestination))
	}

	// 10. Success.
	return dst, nil
}

// monotonicNowNS reads CLOCK_MONOTONIC in nanoseconds. bpf_ktime_get_ns() in
// connect4 is monotonic and unaffected by wall-clock steps, so the freshness
// comparison must read the same clock; time.Now() here would be a bug
// (design §8.1). A read failure returns 0, which makes every entry appear as a
// future stamp and therefore stale - fail-closed.
func monotonicNowNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}
