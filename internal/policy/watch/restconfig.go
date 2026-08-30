package watch

import (
	"errors"
	"fmt"

	"k8s.io/client-go/rest"
)

// ErrInClusterConfig is the bounded closed error wrapping a failure to build the
// in-cluster REST config (e.g. running outside a pod, missing service-account
// token). Callers classify it with errors.Is; the underlying rest error is
// preserved via %w for diagnostics.
var ErrInClusterConfig = errors.New("watch: in-cluster REST config unavailable")

// inClusterConfig is the injectable seam over rest.InClusterConfig so unit tests
// can drive the failure branch without a live pod environment (#95). Production
// uses the real client-go loader.
var inClusterConfig = rest.InClusterConfig

// InClusterRESTConfig returns the client-go in-cluster REST config, wrapping any
// failure in the bounded closed ErrInClusterConfig (#95). On success it returns
// the non-nil *rest.Config unchanged (#96). It performs no live API-server
// validation (that is P9c's job); it only constructs the config.
func InClusterRESTConfig() (*rest.Config, error) {
	cfg, err := inClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInClusterConfig, err)
	}
	return cfg, nil
}
