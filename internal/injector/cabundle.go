package injector

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/girishmotwani/aksh/internal/audit"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

// caBundleReconciler patches the current CA PEM into the caBundle of both the
// mutating and validating webhook configurations and observes their state.
type caBundleReconciler struct {
	client         kubernetes.Interface
	mutatingName   string
	validatingName string
	logger         *slog.Logger
	metrics        audit.MetricsRecorder
}

// obsLogger returns a non-nil logger, defaulting to a discard logger so a
// directly-constructed reconciler (tests) never needs to set one.
func (rc *caBundleReconciler) obsLogger() *slog.Logger {
	if rc.logger != nil {
		return rc.logger
	}
	return discardLogger()
}

// obsMetrics returns a non-nil metrics recorder, defaulting to the no-op
// recorder so a directly-constructed reconciler never needs to set one.
func (rc *caBundleReconciler) obsMetrics() audit.MetricsRecorder {
	if rc.metrics != nil {
		return rc.metrics
	}
	return audit.NopMetricsRecorder{}
}

// reconcile patches the current CA PEM into both webhook configurations,
// reading the current object before each update and retrying on conflict. It
// refuses an empty CA PEM so a bootstrap or logic error can never clear an
// existing trust root and break admission fail-closed.
func (rc *caBundleReconciler) reconcile(ctx context.Context, caPEM []byte) error {
	if len(caPEM) == 0 {
		return fmt.Errorf("refusing to reconcile empty CA PEM")
	}
	if err := rc.reconcileMutating(ctx, caPEM); err != nil {
		return fmt.Errorf("reconcile mutating webhook configuration: %w", err)
	}
	if err := rc.reconcileValidating(ctx, caPEM); err != nil {
		return fmt.Errorf("reconcile validating webhook configuration: %w", err)
	}
	return nil
}

func (rc *caBundleReconciler) reconcileMutating(ctx context.Context, caPEM []byte) error {
	api := rc.client.AdmissionregistrationV1().MutatingWebhookConfigurations()
	var patchedRV string
	patched := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cfg, err := api.Get(ctx, rc.mutatingName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		changed := false
		for i := range cfg.Webhooks {
			if !bytes.Equal(cfg.Webhooks[i].ClientConfig.CABundle, caPEM) {
				cfg.Webhooks[i].ClientConfig.CABundle = cloneBytes(caPEM)
				changed = true
			}
		}
		if !changed {
			patched = false
			return nil
		}
		updated, err := api.Update(ctx, cfg, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		patchedRV = updated.ResourceVersion
		patched = true
		return nil
	})
	if err != nil {
		rc.obsMetrics().CABundlePatch(audit.WebhookConfigMutating, audit.PatchResultError)
		return err
	}
	if patched {
		rc.obsMetrics().CABundlePatch(audit.WebhookConfigMutating, audit.PatchResultSuccess)
		rc.obsLogger().Info("aksh-injector: patched webhook caBundle",
			"configuration", audit.WebhookConfigMutating.String(),
			"resourceVersion", patchedRV,
		)
	}
	return nil
}

func (rc *caBundleReconciler) reconcileValidating(ctx context.Context, caPEM []byte) error {
	api := rc.client.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	var patchedRV string
	patched := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cfg, err := api.Get(ctx, rc.validatingName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		changed := false
		for i := range cfg.Webhooks {
			if !bytes.Equal(cfg.Webhooks[i].ClientConfig.CABundle, caPEM) {
				cfg.Webhooks[i].ClientConfig.CABundle = cloneBytes(caPEM)
				changed = true
			}
		}
		if !changed {
			patched = false
			return nil
		}
		updated, err := api.Update(ctx, cfg, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
		patchedRV = updated.ResourceVersion
		patched = true
		return nil
	})
	if err != nil {
		rc.obsMetrics().CABundlePatch(audit.WebhookConfigValidating, audit.PatchResultError)
		return err
	}
	if patched {
		rc.obsMetrics().CABundlePatch(audit.WebhookConfigValidating, audit.PatchResultSuccess)
		rc.obsLogger().Info("aksh-injector: patched webhook caBundle",
			"configuration", audit.WebhookConfigValidating.String(),
			"resourceVersion", patchedRV,
		)
	}
	return nil
}

// bundlesConsistent reports whether every webhook in both configurations
// carries the non-empty current CA PEM.
func (rc *caBundleReconciler) bundlesConsistent(ctx context.Context, caPEM []byte) (bool, error) {
	if len(caPEM) == 0 {
		return false, nil
	}

	mutating, err := rc.client.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx, rc.mutatingName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	if !mutatingBundlesMatch(mutating.Webhooks, caPEM) {
		return false, nil
	}

	validating, err := rc.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, rc.validatingName, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	return validatingBundlesMatch(validating.Webhooks, caPEM), nil
}

func mutatingBundlesMatch(webhooks []admissionregistrationv1.MutatingWebhook, caPEM []byte) bool {
	if len(webhooks) == 0 {
		return false
	}
	for i := range webhooks {
		if !bytes.Equal(webhooks[i].ClientConfig.CABundle, caPEM) {
			return false
		}
	}
	return true
}

func validatingBundlesMatch(webhooks []admissionregistrationv1.ValidatingWebhook, caPEM []byte) bool {
	if len(webhooks) == 0 {
		return false
	}
	for i := range webhooks {
		if !bytes.Equal(webhooks[i].ClientConfig.CABundle, caPEM) {
			return false
		}
	}
	return true
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
