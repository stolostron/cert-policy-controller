// Copyright Contributors to the Open Cluster Management project

package v1

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RemediationAction : enforce or inform
type RemediationAction string

const (
	// Enforce is an remediationAction to make changes
	Enforce RemediationAction = "Enforce"

	// Inform is an remediationAction to only inform
	Inform RemediationAction = "Inform"
)

// ComplianceState shows the state of enforcement
type ComplianceState string

const (
	// Compliant is an ComplianceState
	Compliant ComplianceState = "Compliant"

	// NonCompliant is an ComplianceState
	NonCompliant ComplianceState = "NonCompliant"

	// UnknownCompliancy is an ComplianceState
	UnknownCompliancy ComplianceState = "UnknownCompliancy"
)

// A custom type is required since there is no way to have a kubebuilder marker
// apply to the items of a slice.

// +kubebuilder:validation:MinLength=1
type NonEmptyString string

type Target struct {
	// 'include' is an array of filepath expressions to include objects by name.
	Include []NonEmptyString `json:"include,omitempty"`
	// 'exclude' is an array of filepath expressions to exclude objects by name.
	Exclude []NonEmptyString `json:"exclude,omitempty"`
	// 'matchLabels' is a map of {key,value} pairs matching objects by label.
	MatchLabels *map[string]string `json:"matchLabels,omitempty"`
	// 'matchExpressions' is an array of label selector requirements matching objects by label.
	MatchExpressions *[]metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// Define String() so that the LabelSelector is dereferenced in the logs
func (t Target) String() string {
	fmtSelectorStr := "{include:%s,exclude:%s,matchLabels:%+v,matchExpressions:%+v}"
	if t.MatchLabels == nil && t.MatchExpressions == nil {
		return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, nil, nil)
	}

	if t.MatchLabels == nil {
		return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, nil, *t.MatchExpressions)
	}

	if t.MatchExpressions == nil {
		return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, *t.MatchLabels, nil)
	}

	return fmt.Sprintf(fmtSelectorStr, t.Include, t.Exclude, *t.MatchLabels, *t.MatchExpressions)
}

// CertificatePolicySpec defines the desired state of CertificatePolicy
type CertificatePolicySpec struct {
	// enforce, inform
	// +kubebuilder:validation:Enum=Inform;inform;Enforce;enforce
	RemediationAction RemediationAction `json:"remediationAction,omitempty"`
	// 'namespaceSelector' defines the list of namespaces to include/exclude for objects defined in
	// spec.objectTemplates. All selector rules are ANDed. If 'include' is not provided but
	// 'matchLabels' and/or 'matchExpressions' are, 'include' will behave as if ['*'] were given. If
	// 'matchExpressions' and 'matchLabels' are both not provided, 'include' must be provided to
	// retrieve namespaces.
	NamespaceSelector Target                    `json:"namespaceSelector,omitempty"`
	LabelSelector     map[string]NonEmptyString `json:"labelSelector,omitempty"`
	// low, medium, high, or critical
	// +kubebuilder:validation:Enum=low;Low;medium;Medium;high;High;critical;Critical
	Severity string `json:"severity,omitempty"`
	// Minimum duration before a certificate expires that it is considered non-compliant. Golang's time units only.
	MinDuration *metav1.Duration `json:"minimumDuration,omitempty"`
	// Minimum CA duration before a signing certificate expires that it is considered non-compliant.
	// Golang's time units only.
	MinCADuration *metav1.Duration `json:"minimumCADuration,omitempty"` // nolint:tagliatelle
	// Maximum duration for a certificate, longer duration is considered non-compliant.
	// Golang's time units only.
	MaxDuration *metav1.Duration `json:"maximumDuration,omitempty"`
	// Maximum CA duration for a signing certificate, longer duration is considered non-compliant.
	// Golang's time units only.
	MaxCADuration *metav1.Duration `json:"maximumCADuration,omitempty"` // nolint:tagliatelle
	// A pattern that must match any defined SAN entries in the certificate for the certificate to be compliant.
	//  Golang's regexp syntax only.
	// +kubebuilder:validation:MinLength=1
	AllowedSANPattern string `json:"allowedSANPattern,omitempty"` // nolint:tagliatelle
	// A pattern that must not match any defined SAN entries in the certificate for the certificate to be compliant.
	// Golang's regexp syntax only.
	// +kubebuilder:validation:MinLength=1
	DisallowedSANPattern string `json:"disallowedSANPattern,omitempty"` // nolint:tagliatelle
}

// CertificatePolicyStatus defines the observed state of CertificatePolicy
type CertificatePolicyStatus struct {
	// Compliant, NonCompliant, UnknownCompliancy
	ComplianceState ComplianceState `json:"compliant,omitempty"`
	// map of namespaces to its compliancy details
	CompliancyDetails map[string]CompliancyDetails `json:"compliancyDetails,omitempty"`
}

// CompliancyDetails defines the all the details related to whether or not the policy is compliant
type CompliancyDetails struct {
	NonCompliantCertificates     uint            `json:"nonCompliantCertificates,omitempty"`
	NonCompliantCertificatesList map[string]Cert `json:"nonCompliantCertificatesList,omitempty"`
	Message                      string          `json:"message,omitempty"` // Overall message of this compliance
}

// Cert contains its related secret and when it expires
type Cert struct {
	Secret     string        `json:"secretName,omitempty"`
	Expiration string        `json:"expiration,omitempty"`
	Expiry     time.Duration `json:"expiry,omitempty"`
	CA         bool          `json:"ca,omitempty"`
	Duration   time.Duration `json:"duration,omitempty"`
	Sans       []string      `json:"sans,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:path=certificatepolicies,scope=Namespaced

// CertificatePolicy is the Schema for the certificatepolicies API
type CertificatePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificatePolicySpec   `json:"spec,omitempty"`
	Status CertificatePolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// CertificatePolicyList contains a list of CertificatePolicy
type CertificatePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificatePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificatePolicy{}, &CertificatePolicyList{})
}
