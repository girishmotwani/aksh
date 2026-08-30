package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the API group and version used to register these
// types, matching the +groupName marker on the package doc comment.
var GroupVersion = schema.GroupVersion{Group: "aksh.dev", Version: "v1alpha1"}

// SchemeBuilder collects functions that add types to a runtime.Scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds the types in this group-version to the given scheme,
// registering AkshPolicy and AkshPolicyList so they satisfy
// runtime.Object and can be served by a Kubernetes API server or client.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&AkshPolicy{},
		&AkshPolicyList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
