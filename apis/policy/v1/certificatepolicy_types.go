// Copyright Contributors to the Open Cluster Management project

package v1

import (
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

// Target defines the list of namespaces to include/exclude
type Target struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// CertificatePolicySpec defines the desired state of CertificatePolicy
type CertificatePolicySpec struct {
	//enforce, inform
	RemediationAction RemediationAction `json:"remediationAction,omitempty"`
	// selecting a list of namespaces where the policy applies
	NamespaceSelector Target            `json:"namespaceSelector,omitempty"`
	LabelSelector     map[string]string `json:"labelSelector,omitempty"`
	// low, medium, or high
	Severity string `json:"severity,omitempty"`
	// Minimum duration before a certificate expires that it is considered non-compliant. Golang's time units only
	MinDuration *metav1.Duration `json:"minimumDuration,omitempty"`
	// Minimum CA duration before a signing certificate expires that it is considered non-compliant.
	// Golang's time units only
	MinCADuration *metav1.Duration `json:"minimumCADuration,omitempty"`
	// Maximum duration for a certificate, longer duration is considered non-compliant.
	// Golang's time units only
	MaxDuration *metav1.Duration `json:"maximumDuration,omitempty"`
	// Maximum CA duration for a signing certificate, longer duration is considered non-compliant.
	// Golang's time units only
	MaxCADuration *metav1.Duration `json:"maximumCADuration,omitempty"`
	// A pattern that must match any defined SAN entries in the certificate for the certificate to be compliant.
	//  Golang's regexp symtax only
	AllowedSANPattern string `json:"allowedSANPattern,omitempty"`
	// A pattern that must not match any defined SAN entries in the certificate for the certificate to be compliant.
	// Golang's regexp symtax only
	DisallowedSANPattern string `json:"disallowedSANPattern,omitempty"`
}

// CertificatePolicyStatus defines the observed state of CertificatePolicy
type CertificatePolicyStatus struct {
	// Compliant, NonCompliant, UnkownCompliancy
	ComplianceState ComplianceState `json:"compliant,omitempty"`
	// map of namespaces to its compliancy details
	CompliancyDetails map[string]CompliancyDetails `json:"compliancyDetails,omitempty"`
}

// CompliancyDetails defines the all the details related to whether or not the policy is compliant
type CompliancyDetails struct {
	NonCompliantCertificates     uint            `json:"NonCompliantCertificates,omitempty"`
	NonCompliantCertificatesList map[string]Cert `json:"NonCompliantCertificatesList,omitempty"`
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

// Policy is a specification for a Policy resource
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
}

//+kubebuilder:object:root=true

// CertificatePolicyList contains a list of CertificatePolicy
type CertificatePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificatePolicy `json:"items"`
}

//+kubebuilder:object:root=true

// PolicyList is a list of Policy resources
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Policy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificatePolicy{}, &CertificatePolicyList{})
	SchemeBuilder.Register(&Policy{}, &PolicyList{})
}
