//go:build linux

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	bpf "github.com/girishmotwani/aksh/internal/dataplane/bpf"
)

// Loader-runtime sentinels named by the unit test specification (§9, rows
// #101-#118). They live in the Linux file because the composer only exists on
// Linux; the non-Linux stub in loader_other.go returns ErrUnsupportedPlatform
// before any of these can be reached.
var (
	// ErrAlreadyAttached reports a second LoadAndAttach on an *Options that is
	// already loaded and attached; the first call's kernel objects are retained
	// and the second is refused rather than double-loading (#116).
	ErrAlreadyAttached = errors.New("capture: programs are already attached for these options")
	// errAttachLost is the health-check verdict that a program is no longer
	// attached where it was pinned; it drives the ERROR log and process exit of
	// design section 6.8.5 (#109, #110).
	errAttachLost = errors.New("capture: attachment lost")
)

// attachSpecs is the fixed (program, cgroup attach type) table of design
// section 6.8.2 step 6, mirroring the internal/dataplane/bpf README table.
var attachSpecs = []struct {
	name   string
	attach ebpf.AttachType
}{
	{bpf.AkshbpfProgAkshConnect4, ebpf.AttachCGroupInet4Connect},
	{bpf.AkshbpfProgAkshConnect6Deny, ebpf.AttachCGroupInet6Connect},
	{bpf.AkshbpfProgAkshSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
	{bpf.AkshbpfProgAkshSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	{bpf.AkshbpfProgAkshSockCreate, ebpf.AttachCGroupInetSockCreate},
	{bpf.AkshbpfProgAkshSockops, ebpf.AttachCGroupSockOps},
}

// loaderSyscalls is the unexported, Linux-only seam over every kernel and OS
// dependency the load sequence touches that a test must be able to force or
// observe: the kernel-version check (#117), the object load (#102, #115, #118),
// and the health-check loop's tick, verdict, exit and log (#109, #110).
// Production wires the real implementations; ebpf_integration tests replace
// individual fields, exactly as privDropSeam is used for the privilege drop.
type loaderSyscalls struct {
	kernelVersion      func() (KernelVersion, error)
	loadCollectionSpec func() (*ebpf.CollectionSpec, error)
	newCollection      func(*ebpf.CollectionSpec) (*ebpf.Collection, error)
	newHealthTicker    func(time.Duration) (<-chan time.Time, func())
	checkAttachment    func(*loaderState) error
	programID          func(*ebpf.Program) (uint32, error)
	exit               func(int)
	log                *slog.Logger
}

// loaderSeam is the live seam LoadAndAttach reads. It is a package variable so
// tests can swap fields; production initialises it to the real dependencies.
var loaderSeam = defaultLoaderSyscalls()

func defaultLoaderSyscalls() loaderSyscalls {
	return loaderSyscalls{
		kernelVersion:      defaultKernelVersion,
		loadCollectionSpec: bpf.LoadAkshbpf,
		newCollection:      func(spec *ebpf.CollectionSpec) (*ebpf.Collection, error) { return ebpf.NewCollection(spec) },
		newHealthTicker:    defaultHealthTicker,
		checkAttachment:    defaultCheckAttachment,
		programID:          defaultProgramID,
		exit:               os.Exit,
		log:                slog.Default(),
	}
}

// attachedLink bundles one attached program with the link that keeps it
// attached and the kernel program id recorded at attach time (design 6.8.2
// step 8).
type attachedLink struct {
	name   string
	link   link.Link
	progID uint32
	attach ebpf.AttachType
}

// loaderState holds the kernel objects a successful load retains for the life
// of the process: the collection, the frozen config map, the attach links and
// their pins. It is fail-closed - closeAll unwinds every object created so far
// so a partial load leaves nothing behind (#118).
type loaderState struct {
	opts      *Options
	coll      *ebpf.Collection
	configMap *ebpf.Map
	bypassMap *ebpf.Map
	links     []attachedLink
	pinPaths  []string
	info      *AttachInfo
	cancel    context.CancelFunc
	// onLost is the health loop's terminal dispatch, set by the owning Handle.
	// It replaces the removed os.Exit(1): on a proof of detachment the loop logs
	// at ERROR and calls onLost, letting the orchestrator drive the fail-closed
	// drain instead of the library killing the process.
	onLost func(error)
}

// loadedSet records the live load per *Options so a second LoadAndAttach on the
// same options is refused rather than double-loading (#116).
var (
	loaderMu  sync.Mutex
	loadedSet = map[*Options]*loaderState{}
)

// loaderFor returns the retained loader state for opts, or nil.
func loaderFor(opts *Options) *loaderState {
	loaderMu.Lock()
	defer loaderMu.Unlock()
	return loadedSet[opts]
}

// LoadAndAttach is the Linux load/attach/pin/freeze/verify/health composer of
// design section 6.8.2. It loads the compiled programs, writes and freezes
// aksh_config, cgroup-attaches every program, optionally pins the links under a
// pin root it proves it exclusively owns (gate P15, 6.8.6), and starts the
// mandatory attachment health check (6.8.5). Every failure unwinds the kernel
// objects created so far and returns a *PreflightError carrying the stable E_*
// code of the step that failed.
func LoadAndAttach(opts *Options) (*Handle, error) {
	if opts == nil {
		return nil, ErrMissingOptions
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	seam := loaderSeam

	// Atomically check the idempotency guard and reserve an in-progress slot so
	// two concurrent callers cannot both pass the guard and double-load,
	// creating duplicate attached programs and leaked kernel objects (#116).
	// The reservation is held for the whole load but loaderMu is not - the
	// expensive syscalls run with the lock released. On any failure the deferred
	// unwind removes the reservation so a later retry can proceed; on success it
	// is left in place already populated with the completed state.
	st := &loaderState{opts: opts}
	loaderMu.Lock()
	if loadedSet[opts] != nil {
		loaderMu.Unlock()
		return nil, ErrAlreadyAttached
	}
	loadedSet[opts] = st
	loaderMu.Unlock()

	success := false
	defer func() {
		if !success {
			loaderMu.Lock()
			if loadedSet[opts] == st {
				delete(loadedSet, opts)
			}
			loaderMu.Unlock()
		}
	}()

	// Kernel floor, before any program is loaded (#117).
	floor := opts.MinKernel
	if floor == (KernelVersion{}) {
		floor = MinSupportedKernel()
	}
	kv, err := seam.kernelVersion()
	if err != nil {
		return nil, newPreflightError("loader", E_KERNEL_TOO_OLD, err)
	}
	if !kv.AtLeast(floor) {
		return nil, newPreflightError("loader", E_KERNEL_TOO_OLD,
			fmt.Errorf("kernel %s is below the %s floor", kv, floor))
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	spec, err := seam.loadCollectionSpec()
	if err != nil {
		return nil, newPreflightError("loader", E_PROG_LOAD, err)
	}
	applyMapSizing(spec, opts)

	coll, err := seam.newCollection(spec)
	if err != nil {
		return nil, classifyLoadError(err)
	}
	st.coll = coll

	// Cancellation observed after real kernel objects exist must unwind them
	// rather than proceed (#118).
	if err := ctx.Err(); err != nil {
		st.closeAll()
		return nil, err
	}

	if err := st.writeAndFreezeConfig(opts); err != nil {
		st.closeAll()
		return nil, err
	}

	if err := st.writeAndFreezeBypass(opts); err != nil {
		st.closeAll()
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		st.closeAll()
		return nil, err
	}

	info, err := st.attach(opts, seam)
	if err != nil {
		st.closeAll()
		return nil, err
	}

	if opts.PinLinks {
		// Gate P15 runs before any BPF_OBJ_PIN syscall (#114, 6.8.6 half one).
		if err := checkPinRootSafe(opts); err != nil {
			st.closeAll()
			return nil, err
		}
		pins, err := st.pinAll(opts)
		if err != nil {
			st.closeAll()
			return nil, err
		}
		info.PinPaths = pins
	}
	st.info = info

	h := newHandle(st, info)
	st.onLost = h.signalAttachLoss

	hctx, cancel := context.WithCancel(ctx)
	st.cancel = cancel
	go st.runHealthLoop(hctx, seam)

	success = true
	return h, nil
}

// writeAndFreezeConfig writes aksh_config, reads it back byte-for-byte and
// freezes only that map (design 6.8.2 steps 4-5). The freeze is irreversible
// and makes every later BPF_MAP_UPDATE_ELEM return EPERM while the programs
// keep reading the map (#103-#108).
func (l *loaderState) writeAndFreezeConfig(opts *Options) error {
	l.configMap = l.coll.Maps[bpf.AkshbpfMapAkshConfig]
	if l.configMap == nil {
		return newPreflightError("loader", E_CONFIG_WRITE, errors.New("aksh_config map is absent from the collection"))
	}
	image, err := buildConfigImage(opts)
	if err != nil {
		return newPreflightError("loader", E_CONFIG_WRITE, err)
	}
	if err := l.configMap.Update(uint32(0), image, ebpf.UpdateAny); err != nil {
		return newPreflightError("loader", E_CONFIG_WRITE, err)
	}
	var readback [ConfigImageSize]byte
	if err := l.configMap.Lookup(uint32(0), &readback); err != nil {
		return newPreflightError("loader", E_CONFIG_WRITE, err)
	}
	if !bytes.Equal(image, readback[:]) {
		return newPreflightError("loader", E_CONFIG_WRITE,
			fmt.Errorf("config readback %x differs from the written image %x", readback[:], image))
	}
	if err := l.configMap.Freeze(); err != nil {
		return newPreflightError("loader", E_CONFIG_FREEZE, err)
	}
	return nil
}

// writeAndFreezeBypass fills bypass_cidr4 with the configured unpoliced
// prefixes, reads each one back, and freezes the map.
//
// The freeze is the security-relevant half. Every entry here is a destination
// the programs will not redirect, so a map that stayed writable after attach
// would let a proxy holding CAP_BPF insert a prefix covering anything it wanted
// to reach unobserved. Freezing an empty map is not a no-op for the same
// reason, so it happens whether or not any prefix is configured.
func (l *loaderState) writeAndFreezeBypass(opts *Options) error {
	l.bypassMap = l.coll.Maps[bpf.AkshbpfMapBypassCidr4]
	if l.bypassMap == nil {
		return newPreflightError("loader", E_CONFIG_WRITE, errors.New("bypass_cidr4 map is absent from the collection"))
	}
	for _, p := range opts.BypassCIDRs {
		key, err := bypassKeyFor(p)
		if err != nil {
			return newPreflightError("loader", E_CONFIG_WRITE, err)
		}
		if err := l.bypassMap.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return newPreflightError("loader", E_CONFIG_WRITE, fmt.Errorf("write bypass prefix %v: %w", p, err))
		}
		var readback uint8
		if err := l.bypassMap.Lookup(key, &readback); err != nil {
			return newPreflightError("loader", E_CONFIG_WRITE, fmt.Errorf("read back bypass prefix %v: %w", p, err))
		}
		if readback != 1 {
			return newPreflightError("loader", E_CONFIG_WRITE,
				fmt.Errorf("bypass prefix %v read back as %d, want 1", p, readback))
		}
	}
	if err := l.bypassMap.Freeze(); err != nil {
		return newPreflightError("loader", E_CONFIG_FREEZE, err)
	}
	return nil
}

// attach cgroup-attaches every program, records the real program ids and the
// real cgroup id, and re-reads the kernel program ids to confirm the attach
// took (design 6.8.2 steps 6, 8).
func (l *loaderState) attach(opts *Options, seam loaderSyscalls) (*AttachInfo, error) {
	cgID, err := cgroupID(opts.PodPath)
	if err != nil {
		return nil, newPreflightError("loader", E_ATTACH, fmt.Errorf("resolve cgroup id: %w", err))
	}
	progIDs := make([]uint32, 0, len(attachSpecs))
	for _, as := range attachSpecs {
		prog := l.coll.Programs[as.name]
		if prog == nil {
			return nil, newPreflightError("loader", E_ATTACH, fmt.Errorf("program %s is absent from the collection", as.name))
		}
		lk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    opts.PodPath,
			Attach:  as.attach,
			Program: prog,
		})
		if err != nil {
			return nil, newPreflightError("loader", E_ATTACH, fmt.Errorf("attach %s: %w", as.name, err))
		}
		id, err := seam.programID(prog)
		if err != nil {
			// The link exists but its program id could not be established; a
			// zero/placeholder id must never reach AttachInfo (#101), so close
			// the just-created link and fail closed - closeAll unwinds the
			// links recorded before this one.
			_ = lk.Close()
			return nil, newPreflightError("loader", E_ATTACH, fmt.Errorf("read program id for %s: %w", as.name, err))
		}
		if id == 0 {
			// Defense-in-depth: even a seam override must never yield a zero
			// (placeholder) program id (#101). Fail closed and unwind.
			_ = lk.Close()
			return nil, newPreflightError("loader", E_ATTACH, fmt.Errorf("program %s reported a zero id", as.name))
		}
		l.links = append(l.links, attachedLink{name: as.name, link: lk, progID: id, attach: as.attach})
		progIDs = append(progIDs, id)
	}
	return &AttachInfo{ProgIDs: progIDs, CgroupID: cgID}, nil
}

// pinAll pins every link and pair_orig_dst under <pinRoot>/aksh/<podUID> and
// chowns each pin to the post-drop proxy uid so the dropped process can
// BPF_OBJ_GET it (design 6.8.2 step 7; README constraint 2, #111).
func (l *loaderState) pinAll(opts *Options) ([]string, error) {
	base := filepath.Join(opts.PinRoot, "aksh", podUIDFromPath(opts.PodPath))
	var pins []string
	pinOne := func(name string, do func(string) error) error {
		p := filepath.Join(base, name)
		if err := do(p); err != nil {
			return newPreflightError("loader", E_ATTACH, fmt.Errorf("pin %s: %w", name, err))
		}
		l.pinPaths = append(l.pinPaths, p)
		if err := unix.Chown(p, int(opts.ProxyUID), int(opts.ProxyGID)); err != nil {
			return newPreflightError("loader", E_PIN_ROOT_UNSAFE, fmt.Errorf("chown pin %s: %w", p, err))
		}
		pins = append(pins, p)
		return nil
	}
	for i := range l.links {
		al := &l.links[i]
		if err := pinOne(al.name+".link", al.link.Pin); err != nil {
			return nil, err
		}
	}
	pairMap := l.coll.Maps[bpf.AkshbpfMapPairOrigDst]
	if pairMap == nil {
		return nil, newPreflightError("loader", E_ATTACH,
			fmt.Errorf("map %s is absent from the collection", bpf.AkshbpfMapPairOrigDst))
	}
	if err := pinOne(bpf.AkshbpfMapPairOrigDst, pairMap.Pin); err != nil {
		return nil, err
	}
	return pins, nil
}

// runHealthLoop re-verifies attachment on every tick and, on a proof of
// detachment (or three consecutive inconclusive checks), logs
// capture.attach_lost at ERROR and dispatches the fail-closed attach-loss
// signal through the owning Handle (onLost) instead of calling os.Exit (design
// section 6.8.5, DD-2; Findings Improvement #2 anti-pattern removal). It stops
// when the context is cancelled.
func (l *loaderState) runHealthLoop(ctx context.Context, seam loaderSyscalls) {
	ch, stop := seam.newHealthTicker(l.opts.AttachCheckInterval)
	defer stop()
	inconclusive := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			err := seam.checkAttachment(l)
			if err == nil {
				inconclusive = 0
				continue
			}
			if isInconclusive(err) {
				inconclusive++
				seam.log.Warn("capture.attach_check_inconclusive", "error", err.Error(), "count", inconclusive)
				if inconclusive < 3 {
					continue
				}
			}
			seam.log.Error("capture.attach_lost", "error", err.Error())
			if l.onLost != nil {
				l.onLost(err)
			}
			return
		}
	}
}

// closeAll unwinds every retained kernel object, so a failed or cancelled load
// leaves no maps, links or pins behind (fail-closed, #118). It is safe to call
// on a partially built state and more than once.
func (l *loaderState) closeAll() {
	loaderMu.Lock()
	if loadedSet[l.opts] == l {
		delete(loadedSet, l.opts)
	}
	loaderMu.Unlock()

	if l.cancel != nil {
		l.cancel()
	}
	for i := range l.links {
		if lk := l.links[i].link; lk != nil {
			_ = lk.Unpin()
			_ = lk.Close()
		}
	}
	for _, p := range l.pinPaths {
		_ = os.Remove(p)
	}
	if l.coll != nil {
		l.coll.Close()
	}
}

// checkPinRootSafe is design section 6.8.6 half one: it proves the pin subtree
// is a bpffs directory this process exclusively owns at mode 0700 before any
// pin is written. A pre-existing directory with the wrong owner or mode is
// refused, not repaired (E_PIN_ROOT_UNSAFE); it returns before any BPF_OBJ_PIN
// syscall (#114).
func checkPinRootSafe(opts *Options) error {
	var sfs unix.Statfs_t
	if err := unix.Statfs(opts.PinRoot, &sfs); err != nil {
		return newPreflightError("P15", E_NO_BPFFS, err)
	}
	if uint32(sfs.Type) != BPFFSMagic {
		return newPreflightError("P15", E_NO_BPFFS,
			fmt.Errorf("%s has filesystem magic %#x, want bpffs %#x", opts.PinRoot, uint32(sfs.Type), BPFFSMagic))
	}
	dirs := []string{
		filepath.Join(opts.PinRoot, "aksh"),
		filepath.Join(opts.PinRoot, "aksh", podUIDFromPath(opts.PodPath)),
	}
	for _, dir := range dirs {
		created := false
		if err := os.Mkdir(dir, 0o700); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return newPreflightError("P15", E_PIN_ROOT_UNSAFE, err)
			}
		} else {
			created = true
		}
		if created {
			if err := unix.Chown(dir, int(opts.ProxyUID), int(opts.ProxyGID)); err != nil {
				return newPreflightError("P15", E_PIN_ROOT_UNSAFE, err)
			}
		}
		var st unix.Stat_t
		if err := unix.Lstat(dir, &st); err != nil {
			return newPreflightError("P15", E_PIN_ROOT_UNSAFE, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return newPreflightError("P15", E_PIN_ROOT_UNSAFE, fmt.Errorf("%s is not a directory", dir))
		}
		if st.Uid != opts.ProxyUID || st.Gid != opts.ProxyGID {
			return newPreflightError("P15", E_PIN_ROOT_UNSAFE,
				fmt.Errorf("%s is owned by %d:%d, want %d:%d", dir, st.Uid, st.Gid, opts.ProxyUID, opts.ProxyGID))
		}
		if st.Mode&0o777 != 0o700 {
			return newPreflightError("P15", E_PIN_ROOT_UNSAFE,
				fmt.Errorf("%s has mode %#o, want 0700", dir, st.Mode&0o777))
		}
	}
	return nil
}

// classifyLoadError maps a NewCollection failure onto its stable E_* code: a
// verifier rejection is E_PROG_LOAD (#102); a memlock/out-of-memory failure is
// E_MEMLOCK (#115). The loader deliberately does not raise RLIMIT_MEMLOCK - gate
// P8 owns that - so a memlock failure here is a real resource error, not a
// missing raise.
func classifyLoadError(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return newPreflightError("loader", E_PROG_LOAD, err)
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOMEM) {
		return newPreflightError("loader", E_MEMLOCK, err)
	}
	return newPreflightError("loader", E_PROG_LOAD, err)
}

// applyMapSizing overrides the destination maps' max_entries from Options,
// leaving the single-entry aksh_config array untouched (design 6.8.2 step 2).
func applyMapSizing(spec *ebpf.CollectionSpec, opts *Options) {
	if opts.MapEntries == 0 {
		return
	}
	for _, name := range []string{bpf.AkshbpfMapCookieOrigDst, bpf.AkshbpfMapPairOrigDst} {
		if ms := spec.Maps[name]; ms != nil {
			ms.MaxEntries = opts.MapEntries
		}
	}
}

// defaultCheckAttachment is the reduced-mode health check: with no external
// actor able to reach the links (the process holds the only fds), it asserts
// each link fd is still valid. The pinned-link re-open check of design 6.8.5 is
// exercised by the ebpf_integration tests through the seam.
func defaultCheckAttachment(l *loaderState) error {
	for i := range l.links {
		if lk := l.links[i].link; lk != nil {
			if _, err := lk.Info(); err != nil {
				return fmt.Errorf("link %s: %w", l.links[i].name, errAttachLost)
			}
		}
	}
	return nil
}

// isInconclusive reports whether a health-check error is a transient
// "cannot tell" rather than a proof of detachment (design 6.8.5).
func isInconclusive(err error) bool {
	return errors.Is(err, unix.EINTR) || errors.Is(err, unix.ENOMEM)
}

// defaultHealthTicker is the production tick source: a time.Ticker at the
// configured interval.
func defaultHealthTicker(d time.Duration) (<-chan time.Time, func()) {
	tk := time.NewTicker(d)
	return tk.C, tk.Stop
}

// defaultKernelVersion reads the running kernel version from uname(2).
func defaultKernelVersion() (KernelVersion, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return KernelVersion{}, err
	}
	return ParseKernelVersion(unix.ByteSliceToString(u.Release[:]))
}

// defaultProgramID returns the kernel program id of a loaded program. A failure
// to read the program info, an absent id, or a zero id is an error rather than a
// silently accepted 0, so AttachInfo.ProgIDs can never carry a placeholder id
// (#101). Callers must fail closed on the error.
func defaultProgramID(p *ebpf.Program) (uint32, error) {
	info, err := p.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, errors.New("kernel did not report a program id")
	}
	if uint32(id) == 0 {
		return 0, errors.New("kernel reported a zero program id")
	}
	return uint32(id), nil
}

// cgroupID returns the kernel cgroup id of a cgroup2 directory, which is its
// kernfs inode number.
func cgroupID(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// podUIDFromPath derives the <podUID> pin-path segment from the resolved pod
// cgroup basename (design 6.8.2). A basename that is unusable as a path segment
// falls back to a fixed label so a pin path is always well formed.
func podUIDFromPath(path string) string {
	base := filepath.Base(filepath.Clean(path))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "pod"
	}
	return base
}
