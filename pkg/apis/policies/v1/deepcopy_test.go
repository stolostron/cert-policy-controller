// Copyright 2019 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Copyright Contributors to the Open Cluster Management project

package v1

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var certPolicy = CertificatePolicy{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "default",
	}}

var certPolicySpec = CertificatePolicySpec{
	Severity:                        "high",
	RemediationAction:               "enforce",
	MinDuration:                     &metav1.Duration{time.Hour * 24 * 35},
}

var typeMeta = metav1.TypeMeta{
	Kind:       "Policy",
	APIVersion: "v1",
}

var objectMeta = metav1.ObjectMeta{
	Name:      "foo",
	Namespace: "default",
}

var listMeta = metav1.ListMeta{
	Continue: "continue",
}

var items = []CertificatePolicy{}

func TestPolicyDeepCopyInto(t *testing.T) {
	policy := Policy{
		ObjectMeta: objectMeta,
		TypeMeta:   typeMeta,
	}
	policy2 := Policy{}
	policy.DeepCopyInto(&policy2)
	assert.True(t, reflect.DeepEqual(policy, policy2))
}

func TestPolicyDeepCopy(t *testing.T) {
	typeMeta := metav1.TypeMeta{
		Kind:       "Policy",
		APIVersion: "v1",
	}

	objectMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "default",
	}

	policy := Policy{
		ObjectMeta: objectMeta,
		TypeMeta:   typeMeta,
	}
	policy2 := policy.DeepCopy()
	assert.True(t, reflect.DeepEqual(policy, *policy2))
}

func TestCertificatePolicyDeepCopyInto(t *testing.T) {
	policy2 := CertificatePolicy{}
	certPolicy.DeepCopyInto(&policy2)
	assert.True(t, reflect.DeepEqual(certPolicy, policy2))
}

func TestCertificatePolicyDeepCopy(t *testing.T) {
	policy := CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		}}
	policy2 := policy.DeepCopy()
	assert.True(t, reflect.DeepEqual(policy, *policy2))
}

func TestCertificatePolicySpecDeepCopyInto(t *testing.T) {
	policySpec2 := CertificatePolicySpec{}
	certPolicySpec.DeepCopyInto(&policySpec2)
	assert.True(t, reflect.DeepEqual(certPolicySpec, policySpec2))
}

func TestCertificatePolicySpecDeepCopy(t *testing.T) {
	policySpec2 := certPolicySpec.DeepCopy()
	assert.True(t, reflect.DeepEqual(certPolicySpec, *policySpec2))
}

func TestCertificatePolicyListDeepCopy(t *testing.T) {
	items = append(items, certPolicy)
	certPolicyList := CertificatePolicyList{
		TypeMeta: typeMeta,
		ListMeta: listMeta,
		Items:    items,
	}
	certPolicyList2 := certPolicyList.DeepCopy()
	assert.True(t, reflect.DeepEqual(certPolicyList, *certPolicyList2))
}

func TestCertificatePolicyListDeepCopyInto(t *testing.T) {
	items = append(items, certPolicy)
	certPolicyList := CertificatePolicyList{
		TypeMeta: typeMeta,
		ListMeta: listMeta,
		Items:    items,
	}
	certPolicyList2 := CertificatePolicyList{}
	certPolicyList.DeepCopyInto(&certPolicyList2)
	assert.True(t, reflect.DeepEqual(certPolicyList, certPolicyList2))
}

func TestCertificatePolicyStatusDeepCopy(t *testing.T) {
	certList := map[string]Cert{}
	cert := Cert{
		Secret: "secret",
		Expiration: "expired",
	}

	certList["a"] = cert

	compliancyDetails := CompliancyDetails{
		NonCompliantCertificates: 1,
		NonCompliantCertificatesList: certList,
		Message: "A message for you sir",
	}
	detailList := map[string]CompliancyDetails{}
	detailList["b"] = compliancyDetails
	certPolicyStatus := CertificatePolicyStatus{
		ComplianceState:   "Compliant",
		CompliancyDetails: detailList,
	}
	certPolicyStatus2 := certPolicyStatus.DeepCopy()
	assert.True(t, reflect.DeepEqual(certPolicyStatus, *certPolicyStatus2))
}

func TestCertificatePolicyStatusDeepCopyInto(t *testing.T) {
	certList := map[string]Cert{}
        cert := Cert{
                Secret: "secret",
                Expiration: "expired",
        }

        certList["a"] = cert

        compliancyDetails := CompliancyDetails{
                NonCompliantCertificates: 1,
                NonCompliantCertificatesList: certList,
                Message: "A message for you sir",
        }
        detailList := map[string]CompliancyDetails{}
        detailList["b"] = compliancyDetails
        certPolicyStatus := CertificatePolicyStatus{
                ComplianceState:   "Compliant",
                CompliancyDetails: detailList,
        }
	var certPolicyStatus2 CertificatePolicyStatus
	certPolicyStatus.DeepCopyInto(&certPolicyStatus2)
	assert.True(t, reflect.DeepEqual(certPolicyStatus, certPolicyStatus2))
}
