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

package certificatepolicy

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policiesv1 "github.com/stolostron/cert-policy-controller/pkg/apis/policies/v1"
)

func TestConvertPolicyStatusToString(t *testing.T) {
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{time.Hour * 24 * 35},
		},
		Status: policiesv1.CertificatePolicyStatus{
			ComplianceState: policiesv1.NonCompliant,
			CompliancyDetails: map[string]policiesv1.CompliancyDetails{
				"default": {
					NonCompliantCertificates: 1,
					NonCompliantCertificatesList: map[string]policiesv1.Cert{
						"secretName": {
							Secret:     "secretName",
							Expiration: "36h",
							Expiry:     259200000000000,
							Duration:   7776000000000000,
						},
					},
					Message: "NonCompliant; blah",
				},
			},
		},
	}

	policyString := convertPolicyStatusToString(instance, time.Hour*24*10)
	assert.True(t, strings.HasPrefix(policyString, "NonCompliant; "))

	instance = &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{time.Hour * 24 * 35},
		},
		Status: policiesv1.CertificatePolicyStatus{
			ComplianceState: "",
		},
	}
	policyString = convertPolicyStatusToString(instance, time.Hour*300)
	assert.True(t, policyString == "ComplianceState is still undetermined")

	instance.Status.ComplianceState = policiesv1.Compliant
	policyString = convertPolicyStatusToString(instance, time.Hour*24*3)
	assert.NotNil(t, policyString)
}
