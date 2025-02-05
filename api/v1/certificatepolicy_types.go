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

// ComplianceState reports the compliance that results from parameters of the certificate policy.
//
// +kubebuilder:validation:Enum=Compliant;NonCompliant
type ComplianceState string

const (
	Compliant         ComplianceState = "Compliant"
	NonCompliant      ComplianceState = "NonCompliant"
	UnknownCompliancy ComplianceState = ""
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

// CertificatePolicySpec defines which certificates need to be checked and how those certificates
// should be configured to be compliant with the policy. Enforce remediation action is not currently
// supported, so you are responsible to take actions to fix any noncompliant certificates.
type CertificatePolicySpec struct {
	// RemediationAction must be set to "Inform". Enforce is not currently supported, so setting this
	// to "Enforce" has the same effect as "Inform".
	RemediationAction RemediationAction `json:"remediationAction,omitempty"`

	// NamespaceSelector determines namespaces on the managed cluster in which to validate
	// certificates. The Include and Exclude parameters accept file path expressions to include and
	// exclude namespaces by name. The MatchExpressions and MatchLabels parameters specify namespaces
	// to include by label. See the Kubernetes labels and selectors documentation. The resulting list
	// is compiled by using the intersection of results from all parameters. You must provide either
	// Include or at least one of MatchExpressions or MatchLabels to retrieve namespaces.
	NamespaceSelector Target `json:"namespaceSelector,omitempty"`

	// LabelSelector restricts the secrets that are checked to the ones that match these labels.
	LabelSelector map[string]NonEmptyString `json:"labelSelector,omitempty"`

	// Severity is a user-defined severity for when a certificate is found out of compliance with this
	// certificate policy. Accepted values are low, medium, high, and critical.
	//
	// +kubebuilder:validation:Enum=low;Low;medium;Medium;high;High;critical;Critical
	Severity string `json:"severity,omitempty"`

	// MinDuration is the minimum duration for the expiration of a certificate, where a value that is
	// lesser than that duration is considered noncompliant. The value follows the Golang duration
	// format 0h0m0s, where hours (h) is the largest accepted unit of time.
	MinDuration *metav1.Duration `json:"minimumDuration,omitempty"`

	// MaxDuration is the maximum duration for the expiration of a certificate, where a value that is
	// greater than that duration is considered noncompliant. The value follows the Golang duration
	// format 0h0m0s, where hours (h) is the largest accepted unit of time.
	MaxDuration *metav1.Duration `json:"maximumDuration,omitempty"`

	// MinCADuration is the minimum duration for the expiration of the certificate authority (CA),
	// where any value lesser than that duration is considered noncompliant. The value follows the
	// Golang duration format 0h0m0s, where hours (h) is the largest accepted unit of time.
	MinCADuration *metav1.Duration `json:"minimumCADuration,omitempty"` //nolint:tagliatelle

	// MaxCADuration is the maximum duration for the expiration of the certificate authority (CA),
	// where a value that is greater than that duration is considered noncompliant. The value follows
	// the Golang duration format 0h0m0s, where hours (h) is the largest accepted unit of time.
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

// Cert reports the related secret and parsed details of a certificate.
type Cert struct {
	// Secret is the name of the secret containing the certificate.
	Secret string `json:"secretName,omitempty"`

	// Expiration is the string representation of the expiration date of the certificate in UTC RFC 3339 format.
	Expiration string `json:"expiration,omitempty"`

	// Expiry is the time.Duration representation of the expiration of the certificate from the time
	// of the report.
	Expiry time.Duration `json:"expiry,omitempty"`

	// CA is a boolean reporting whether the certificate contains a CA.
	CA bool `json:"ca,omitempty"`

	// Duration is the total duration of the certificate by calculating the difference between its
	// NotAfter and NotBefore values.
	Duration time.Duration `json:"duration,omitempty"`

	// Sans is a list of subject alternative names in the certificate.
	Sans []string `json:"sans,omitempty"`
}

// CompliancyDetails reports the details related to whether the policy is compliant.
type CompliancyDetails struct {
	// NonCompliantCertificates reports the total number of noncompliant certificates.
	NonCompliantCertificates uint `json:"nonCompliantCertificates,omitempty"`

	// NonCompliantCertificatesList reports a map of the details for each noncompliant certificate,
	// where the key comes from the "certificate-name" label, "certmanager.k8s.io/certificate-name"
	// label, or defaults to the name of the secret.
	NonCompliantCertificatesList map[string]Cert `json:"nonCompliantCertificatesList,omitempty"`

	// Message is a human-readable summary of the compliance details.
	Message string `json:"message,omitempty"`
}

// CertificatePolicyStatus reports the observed status that results from parameters of the
// certificate policy.
type CertificatePolicyStatus struct {
	ComplianceState ComplianceState `json:"compliant,omitempty"`

	// CompliancyDetails is a map of namespaces to the compliance details of its contained
	// certificates.
	CompliancyDetails map[string]CompliancyDetails `json:"compliancyDetails,omitempty"`
}

// CertificatePolicy is the schema for the certificatepolicies API. Certificate policy monitors
// certificates on a cluster against user-defined restrictions, and it returns a noncompliance
// status if any certificate does not meet the requirements of the parameters. By default the
// certificate policy uses the 'tls.crt' key of a secret to find the certificate, but you can use an
// alternate key if specified in the 'certificate_key_name' label on the secret.
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
