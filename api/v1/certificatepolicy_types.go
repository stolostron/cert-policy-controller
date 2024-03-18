// Copyright Contributors to the Open Cluster Management project

package v1

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:validation:MinLength=1
type NonEmptyString string

// +kubebuilder:validation:Enum=Inform;inform;Enforce;enforce
type RemediationAction string

const (
	// Enforce is an remediationAction to make changes
	Enforce RemediationAction = "Enforce"

	// Inform is an remediationAction to only inform
	Inform RemediationAction = "Inform"
)

// ComplianceState reports the observed status resulting from the policy's definition(s).
//
// +kubebuilder:validation:Enum=Compliant;NonCompliant;UnknownCompliancy
type ComplianceState string

const (
	Compliant         ComplianceState = "Compliant"
	NonCompliant      ComplianceState = "NonCompliant"
	UnknownCompliancy ComplianceState = "UnknownCompliancy"
)

type Target struct {
	// Include is an array of filepath expressions to include objects by name.
	Include []NonEmptyString `json:"include,omitempty"`

	// Exclude is an array of filepath expressions to exclude objects by name.
	Exclude []NonEmptyString `json:"exclude,omitempty"`

	// MatchLabels is a map of {key,value} pairs matching objects by label.
	MatchLabels *map[string]string `json:"matchLabels,omitempty"`

	// MatchExpressions is an array of label selector requirements matching objects by label.
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

// CertificatePolicySpec defines the certificates to be checked and the parameters within which
// those certificates should fall.
type CertificatePolicySpec struct {
	// Set to "Inform". Enforce is not currently supported, so setting this to Enforce will have the
	// same effect as Inform.
	RemediationAction RemediationAction `json:"remediationAction,omitempty"`

	// NamespaceSelector defines the list of namespaces to include/exclude for objects defined in
	// spec.objectTemplates. All selector rules are ANDed. If Include is not provided but
	// MatchLabels and/or MatchExpressions are, Include will behave as if ['*'] were given. If
	// MatchExpressions and MatchLabels are both not provided, Include must be provided to
	// retrieve namespaces.
	NamespaceSelector Target `json:"namespaceSelector,omitempty"`

	// LabelSelector restricts the secrets that will be checked to the ones that match these labels.
	LabelSelector map[string]NonEmptyString `json:"labelSelector,omitempty"`

	// Severity is a user-defined severity for when a certificate is found out of compliance with this
	// certificate policy. Accepted values are low, medium, high, and critical.
	//
	// +kubebuilder:validation:Enum=low;Low;medium;Medium;high;High;critical;Critical
	Severity string `json:"severity,omitempty"`

	// MinDuration is the minimum duration for a certificate's expiration where any shorter duration
	// is considered non-compliant. The value follows the Golang duration format 0h0m0s where hours
	// (h) is the largest accepted unit of time.
	MinDuration *metav1.Duration `json:"minimumDuration,omitempty"`

	// MaxDuration is the maximum duration for a certificate's expiration where any longer duration is
	// considered non-compliant. The value follows the Golang duration format 0h0m0s where hours (h)
	// is the largest accepted unit of time.
	MaxDuration *metav1.Duration `json:"maximumDuration,omitempty"`

	// MinCADuration is the minimum duration for a certificate authority's (CA) expiration where any
	// shorter duration is considered non-compliant. The value follows the Golang duration format
	// 0h0m0s where hours (h) is the largest accepted unit of time.
	MinCADuration *metav1.Duration `json:"minimumCADuration,omitempty"` //nolint:tagliatelle

	// MaxCADuration is the maxiumum duration for a certificate authority's (CA) expiration where any
	// longer duration is considered non-compliant. The value follows the Golang duration format
	// 0h0m0s where hours (h) is the largest accepted unit of time.
	MaxCADuration *metav1.Duration `json:"maximumCADuration,omitempty"` //nolint:tagliatelle

	// AllowedSANPattern is the pattern that must match any defined subject alternative name (SAN)
	// entries in the certificate for the certificate to be compliant. Refer to
	// https://pkg.go.dev/regexp/syntax for the regular expression syntax.
	//
	// +kubebuilder:validation:MinLength=1
	AllowedSANPattern string `json:"allowedSANPattern,omitempty"` //nolint:tagliatelle

	// DisallowedSANPattern is the pattern that must not match any defined subject alternative name
	// (SAN) entries in the certificate for the certificate to be compliant. Refer to
	// https://pkg.go.dev/regexp/syntax for the regular expression syntax.
	//
	// +kubebuilder:validation:MinLength=1
	DisallowedSANPattern string `json:"disallowedSANPattern,omitempty"` //nolint:tagliatelle
}

// Cert reports a certificate's related secret and its parsed details.
type Cert struct {
	// Secret is the name of the secret containing the certificate.
	Secret string `json:"secretName,omitempty"`

	// Expiration is the string representation of the certificate's expiration from the time of the
	// report.
	Expiration string `json:"expiration,omitempty"`

	// Expiry is the time.Duration representation of the certificate's expiration from the time of the
	// report.
	Expiry time.Duration `json:"expiry,omitempty"`

	// CA is a boolean reporting whether the certificate contains a CA.
	CA bool `json:"ca,omitempty"`

	// Duration is the total duration of the certificate by calculating the difference between its
	// NotAfter and NotBefore values.
	Duration time.Duration `json:"duration,omitempty"`

	// Sans is a list of subject alternative names in the certificate.
	Sans []string `json:"sans,omitempty"`
}

// CompliancyDetails reports the details related to whether or not the policy is compliant
type CompliancyDetails struct {
	// NonCompliantCertificates reports the total number of non-compliant certificates.
	NonCompliantCertificates uint `json:"nonCompliantCertificates,omitempty"`

	// NonCompliantCertificatesList reports a map of the details for each non-compliant certificate,
	// where the key comes from the "certificate-name" label, "certmanager.k8s.io/certificate-name"
	// label, or defaults to the name of the secret.
	NonCompliantCertificatesList map[string]Cert `json:"nonCompliantCertificatesList,omitempty"`

	// Message is a human-readable summary of the compliance details.
	Message string `json:"message,omitempty"`
}

// CertificatePolicyStatus reports the observed status resulting from the certificate policy's
// parameters.
type CertificatePolicyStatus struct {
	ComplianceState ComplianceState `json:"compliant,omitempty"`

	// CompliancyDetails is a map of namespaces to the compliance details of its contained
	// certificates.
	CompliancyDetails map[string]CompliancyDetails `json:"compliancyDetails,omitempty"`
}

// CertificatePolicy is the Schema for the certificatepolicies API. Certificate policy monitors
// certificates on a cluster against user-defined restrictions and returns non-compliance if any
// certificate doesn't fall within the parameters. By default the certificate policy uses the
// 'tls.crt' key of a secret to find the certificate, but can use an alternate key if specified in
// the 'certificate_key_name' label on the secret.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=certificatepolicies,scope=Namespaced
type CertificatePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificatePolicySpec   `json:"spec,omitempty"`
	Status CertificatePolicyStatus `json:"status,omitempty"`
}

// CertificatePolicyList contains a list of certificate policies.
//
// +kubebuilder:object:root=true
type CertificatePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificatePolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificatePolicy{}, &CertificatePolicyList{})
}
