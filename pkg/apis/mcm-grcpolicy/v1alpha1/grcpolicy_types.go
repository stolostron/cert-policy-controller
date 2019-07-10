// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.

package v1alpha1

import (
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

// CertPolicySpec defines the desired state of GRCPolicy
type CertPolicySpec struct {
	RemediationAction RemediationAction `json:"remediationAction,omitempty"` //enforce, inform
	NamespaceSelector Target            `json:"namespaceSelector,omitempty"` // selecting a list of namespaces where the policy applies
	LabelSelector     map[string]string `json:"labelSelector,omitempty"`
	MinDuration       *metav1.Duration  `json:"minimumDuration,omitempty"`
}

// CertPolicyStatus defines the observed state of CertPolicy
type CertPolicyStatus struct {
	ComplianceState   ComplianceState              `json:"compliant,omitempty"`         // Compliant, NonCompliant, UnkownCompliancy
	CompliancyDetails map[string]CompliancyDetails `json:"compliancyDetails,omitempty"` // map of namespaces to its compliancy details
}

// CompliancyDetails defines the all the details related to whether or not the policy is compliant
type CompliancyDetails struct {
	NonCompliantCertificates     uint            `json:"nonCompliantCertificates,omitempty"`
	NonCompliantCertificatesList map[string]Cert `json:"nonCompliantCertificatesList,omitEmpty"`
	Message                      string          `json:"message,omitempty"` // Overall message of this compliance
}

// Cert contains its related secret and when it expires
type Cert struct {
	Secret     string `json:"secretName,omitempty"`
	Expiration string `json:"expiration,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertPolicy is the Schema for the certpolicies API
// +k8s:openapi-gen=true
type CertPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertPolicySpec   `json:"spec,omitempty"`
	Status CertPolicyStatus `json:"status,omitempty"`
}

// Policy is a specification for a Policy resource
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CertPolicyList contains a list of CertPolicy
type CertPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertPolicy `json:"items"`
}

// PolicyList is a list of Policy resources
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:lister-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Policy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertPolicy{}, &CertPolicyList{})
	SchemeBuilder.Register(&Policy{}, &PolicyList{})
}
