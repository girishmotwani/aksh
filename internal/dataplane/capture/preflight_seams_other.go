//go:build !linux

package capture

// NewProductionPreflightSeams has no non-Linux implementation: the capture
// datapath is Linux-only, so off-Linux the production environment seams cannot
// be built. It returns ErrUnsupportedPlatform, matching every other non-Linux
// stub in this package, so a cross-compiled build still links.
func NewProductionPreflightSeams(opts *Options) (PreflightSeams, error) {
	_ = opts
	return PreflightSeams{}, ErrUnsupportedPlatform
}
