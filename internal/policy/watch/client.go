package watch

import (
	"context"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kwatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

// akshPolicyGVR is the GroupVersionResource for AkshPolicy CRDs (S2 §: group
// aksh.dev, version v1alpha1). aksh-proxy holds read-only RBAC on this resource
// in its own namespace and nothing else.
var akshPolicyGVR = schema.GroupVersionResource{
	Group:    "aksh.dev",
	Version:  "v1alpha1",
	Resource: "akshpolicies",
}

// dynamicAkshPolicyClient adapts a client-go dynamic client, scoped to a single
// namespace's akshpolicies resource, to the narrow AkshPolicyClient interface.
type dynamicAkshPolicyClient struct {
	resource dynamic.ResourceInterface
}

// NewDynamicAkshPolicyClient returns an AkshPolicyClient backed by a client-go
// dynamic client, scoped to namespace. This is the production seam; unit tests
// supply a fake instead. An empty namespace is rejected (ErrEmptyNamespace):
// a namespaced dynamic client scoped to "" reads akshpolicies across all
// namespaces, which would break the own-namespace-only fail-closed invariant.
// A nil dynamic client is rejected (ErrNilClient) rather than returning an
// adapter that panics on first use.
func NewDynamicAkshPolicyClient(dc dynamic.Interface, namespace string) (AkshPolicyClient, error) {
	if namespace == "" {
		return nil, ErrEmptyNamespace
	}
	if dc == nil {
		return nil, ErrNilClient
	}
	return &dynamicAkshPolicyClient{resource: dc.Resource(akshPolicyGVR).Namespace(namespace)}, nil
}

// List returns all AkshPolicy objects in the client's namespace, converted from
// the dynamic client's unstructured representation.
func (c *dynamicAkshPolicyClient) List(ctx context.Context, opts metav1.ListOptions) (*v1alpha1.AkshPolicyList, error) {
	ul, err := c.resource.List(ctx, opts)
	if err != nil {
		return nil, err
	}
	out := &v1alpha1.AkshPolicyList{}
	out.ResourceVersion = ul.GetResourceVersion()
	out.Items = make([]v1alpha1.AkshPolicy, 0, len(ul.Items))
	for i := range ul.Items {
		p, err := unstructuredToPolicy(&ul.Items[i])
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, p)
	}
	return out, nil
}

// Watch establishes a namespaced watch on akshpolicies from the given resource
// version. The returned events carry unstructured objects; the watcher relists
// to build the complete set, so it does not decode individual event payloads.
func (c *dynamicAkshPolicyClient) Watch(ctx context.Context, opts metav1.ListOptions) (kwatch.Interface, error) {
	return c.resource.Watch(ctx, opts)
}

// unstructuredToPolicy converts a single unstructured AkshPolicy into the typed
// v1alpha1.AkshPolicy.
func unstructuredToPolicy(u *unstructured.Unstructured) (v1alpha1.AkshPolicy, error) {
	var p v1alpha1.AkshPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &p); err != nil {
		return v1alpha1.AkshPolicy{}, err
	}
	return p, nil
}
