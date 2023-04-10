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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	coretypes "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	testclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "open-cluster-management.io/cert-policy-controller/api/v1"
)

func TestReconcile(t *testing.T) {
	name := "foo"
	namespace := "default"
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration:          &metav1.Duration{Duration: time.Hour * 24 * 35},
			AllowedSANPattern:    "[[:alpha:]]",
			DisallowedSANPattern: "[^\\*]",
			MinCADuration:        &metav1.Duration{Duration: time.Hour * 24 * 35},
			MaxCADuration:        &metav1.Duration{Duration: time.Hour * 24 * 35},
			MaxDuration:          &metav1.Duration{Duration: time.Hour * 24 * 35},
		},
	}

	// Objects to track in the fake client.
	objs := []runtime.Object{instance}
	// Register operator types with the runtime scheme.
	s := scheme.Scheme
	s.AddKnownTypes(policiesv1.GroupVersion, instance)

	// Create a fake client to mock API calls.
	cl := fake.NewClientBuilder()
	cl.WithRuntimeObjects(objs...)
	// Create a ReconcileCertificatePolicy object with the scheme and fake client
	r := &CertificatePolicyReconciler{Client: cl.Build(), Scheme: s, Recorder: nil}

	// Mock request to simulate Reconcile() being called on an event for a
	// watched resource .
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}

	res, err := r.Reconcile(context.TODO(), req)
	if err != nil {
		t.Fatalf("reconcile: (%v)", err)
	}

	t.Log(res)
}

func TestPeriodicallyExecCertificatePolicies(t *testing.T) {
	name := "foo"
	namespace := "default"
	typeMeta := metav1.TypeMeta{
		Kind: "namespace",
	}
	objMeta := metav1.ObjectMeta{
		Name: "default",
	}
	ns := coretypes.Namespace{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
	}
	// Mock request to simulate Reconcile() being called on an event for a
	// watched resource .
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{Duration: time.Hour * 24 * 35},
		},
	}

	// Objects to track in the fake client.
	objs := []runtime.Object{instance}
	// Register operator types with the runtime scheme.
	s := scheme.Scheme
	s.AddKnownTypes(policiesv1.GroupVersion, instance)

	// Create a fake client to mock API calls.
	cl := fake.NewClientBuilder()
	cl.WithRuntimeObjects(objs...)

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()
	// Create a ReconcileCertificatePolicy object with the scheme and fake client.
	r := &CertificatePolicyReconciler{Client: cl.Build(), Scheme: s, Recorder: nil, TargetK8sClient: simpleClient}

	_, err := r.TargetK8sClient.CoreV1().Namespaces().Create(context.TODO(), &ns, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Error creating namespace: %s", err)
		assert.Nil(t, err)
	}

	_, err = r.Reconcile(context.TODO(), req)
	if err != nil {
		t.Fatalf("reconcile: (%v)", err)
	}

	tests := []struct {
		description       string
		namespaceSelector policiesv1.NonEmptyString
		complianceState   policiesv1.ComplianceState
		expectedMsg       string
		cacheNamespace    string
	}{
		{
			"Adds policy when namespace exists",
			"default",
			"Compliant",
			"Found 0 non compliant certificates in the namespace default.\n",
			"default",
		},
		{
			"Adds policy when namespace doesn't exist",
			"not-a-namespace",
			"Compliant",
			"Found 0 non compliant certificates, no namespaces were selected.\n",
			"",
		},
	}

	for i, test := range tests {
		i := i
		test := test

		t.Run(
			test.description,
			func(t *testing.T) {
				certPolicy := instance.DeepCopy()
				certPolicy.Name = fmt.Sprintf("%s-%d", certPolicy.Name, i)
				certPolicy.Spec.NamespaceSelector.Include = []policiesv1.NonEmptyString{test.namespaceSelector}

				r.handleAddingPolicy(context.TODO(), certPolicy)
				r.PeriodicallyExecCertificatePolicies(context.TODO(), 1, false)

				policy, found := availablePolicies.GetObject(test.cacheNamespace + "/" + certPolicy.Name)
				assert.True(t, found)
				assert.NotNil(t, policy)
				assert.Equal(t, test.complianceState, policy.Status.ComplianceState)
				assert.Equal(t, test.expectedMsg, policy.Status.CompliancyDetails[test.cacheNamespace].Message)

				handleRemovingPolicy(certPolicy.Name)
				policy, found = availablePolicies.GetObject(test.cacheNamespace + "/" + certPolicy.Name)
				assert.False(t, found)
				assert.Nil(t, policy)
			},
		)
	}
}

func TestCheckComplianceBasedOnDetails(_ *testing.T) {
	certPolicy := policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
	}
	policies := map[string]*policiesv1.CertificatePolicy{}
	policies["policy1"] = &certPolicy

	checkComplianceBasedOnDetails(&certPolicy)
}

func TestCheckComplianceChangeBasedOnDetails(t *testing.T) {
	certPolicy := policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
	}
	flag := checkComplianceChangeBasedOnDetails(&certPolicy)
	assert.False(t, flag)
}

func TestCreateParentPolicy(t *testing.T) {
	certPolicy := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
	}
	ownerReference := metav1.OwnerReference{
		Name: "foo",
	}
	ownerReferences := []metav1.OwnerReference{}
	ownerReferences = append(ownerReferences, ownerReference)
	certPolicy.OwnerReferences = ownerReferences

	r := &CertificatePolicyReconciler{Client: nil, Scheme: nil, Recorder: nil, TargetK8sClient: nil}

	policy := createParentPolicy(certPolicy)
	assert.NotNil(t, policy)
	r.createParentPolicyEvent(certPolicy)
}

func TestHandleAddingPolicy(t *testing.T) {
	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()

	r := &CertificatePolicyReconciler{
		Client: nil, Scheme: nil,
		Recorder: nil, TargetK8sClient: simpleClient,
	}

	typeMeta := metav1.TypeMeta{
		Kind: "namespace",
	}
	objMeta := metav1.ObjectMeta{
		Name: "default",
	}
	ns := &coretypes.Namespace{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
	}

	_, err := simpleClient.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Error creating namespace: %s", err)
	}

	certPolicy := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-handle-adding-policy",
			Namespace: "default",
		},
	}
	certPolicy.Spec.NamespaceSelector.Include = []policiesv1.NonEmptyString{"default"}

	r.handleAddingPolicy(context.TODO(), certPolicy)
	policy, found := availablePolicies.GetObject(certPolicy.Namespace + "/" + certPolicy.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)
	handleRemovingPolicy(certPolicy.Name)
}

func TestPrintMap(_ *testing.T) {
	certPolicy := policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
	}
	policies := map[string]*policiesv1.CertificatePolicy{}
	policies["policy1"] = &certPolicy
	printMap(policies)
}

func TestGetPatternsUsed(t *testing.T) {
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration:          &metav1.Duration{Duration: time.Hour * 24 * 35},
			AllowedSANPattern:    "allowed",
			DisallowedSANPattern: "disallowed",
		},
	}

	pattern := getPatternsUsed(instance)
	assert.Equal(t, fmt.Sprintf("Allowed: %s Disallowed: %s", "allowed", "disallowed"), pattern)
}

func TestIsCertificateCompliant(t *testing.T) {
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration:          &metav1.Duration{Duration: time.Hour * 24 * 10},
			AllowedSANPattern:    "[ab]",
			DisallowedSANPattern: "[\\*]",
			MaxCADuration:        &metav1.Duration{Duration: time.Hour * 24 * 100},
			MaxDuration:          &metav1.Duration{Duration: time.Hour * 24 * 50},
			MinCADuration:        &metav1.Duration{Duration: time.Hour * 24 * 20},
		},
	}

	// all ok
	cert := &policiesv1.Cert{
		Duration:   time.Hour * 24 * 36,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 34,
		Secret:     "test",
		CA:         true,
		Sans:       []string{"a", "b"},
	}
	assert.True(t, isCertificateCompliant(cert, instance))
	assert.False(t, isCertificateExpiring(cert, instance))
	assert.False(t, isCertificateLongDuration(cert, instance))
	assert.False(t, isCertificateSANPatternMismatch(cert, instance))

	// expiring non CA
	cert = &policiesv1.Cert{
		Duration:   time.Hour * 24 * 35,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 9,
		Secret:     "test",
		CA:         false,
		Sans:       []string{"a", "b"},
	}
	assert.False(t, isCertificateCompliant(cert, instance))
	assert.True(t, isCertificateExpiring(cert, instance))
	assert.False(t, isCertificateLongDuration(cert, instance))
	assert.False(t, isCertificateSANPatternMismatch(cert, instance))

	// expiring CA
	cert = &policiesv1.Cert{
		Duration:   time.Hour * 24 * 75,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 19,
		Secret:     "test",
		CA:         true,
		Sans:       []string{"a", "b"},
	}
	assert.False(t, isCertificateCompliant(cert, instance))
	assert.True(t, isCertificateExpiring(cert, instance))
	assert.False(t, isCertificateLongDuration(cert, instance))
	assert.False(t, isCertificateSANPatternMismatch(cert, instance))

	// long duration non CA
	cert = &policiesv1.Cert{
		Duration:   time.Hour * 24 * 60,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 35,
		Secret:     "test",
		CA:         false,
		Sans:       []string{"a", "b"},
	}
	assert.False(t, isCertificateCompliant(cert, instance))
	assert.False(t, isCertificateExpiring(cert, instance))
	assert.True(t, isCertificateLongDuration(cert, instance))
	assert.False(t, isCertificateSANPatternMismatch(cert, instance))

	// long duration CA
	cert = &policiesv1.Cert{
		Duration:   time.Hour * 24 * 120,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 35,
		Secret:     "test",
		CA:         true,
		Sans:       []string{"a", "b"},
	}
	assert.False(t, isCertificateCompliant(cert, instance))
	assert.False(t, isCertificateExpiring(cert, instance))
	assert.True(t, isCertificateLongDuration(cert, instance))
	assert.False(t, isCertificateSANPatternMismatch(cert, instance))

	// allowed pattern fail
	cert = &policiesv1.Cert{
		Duration:   time.Hour * 24 * 45,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 34,
		Secret:     "test",
		CA:         false,
		Sans:       []string{"a", "c"},
	}
	assert.False(t, isCertificateCompliant(cert, instance))
	assert.False(t, isCertificateExpiring(cert, instance))
	assert.False(t, isCertificateLongDuration(cert, instance))
	assert.True(t, isCertificateSANPatternMismatch(cert, instance))

	// disallowed pattern fail
	cert = &policiesv1.Cert{
		Duration:   time.Hour * 24 * 45,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 34,
		Secret:     "test",
		CA:         false,
		Sans:       []string{"*", "b"},
	}
	assert.False(t, isCertificateCompliant(cert, instance))
	assert.False(t, isCertificateExpiring(cert, instance))
	assert.False(t, isCertificateLongDuration(cert, instance))
	assert.True(t, isCertificateSANPatternMismatch(cert, instance))
}

func TestHaveNewNonCompliantCertificate(t *testing.T) {
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration:          &metav1.Duration{Duration: time.Hour * 24 * 10},
			AllowedSANPattern:    "[ab]",
			DisallowedSANPattern: "[\\*]",
			MaxCADuration:        &metav1.Duration{Duration: time.Hour * 24 * 100},
			MaxDuration:          &metav1.Duration{Duration: time.Hour * 24 * 50},
			MinCADuration:        &metav1.Duration{Duration: time.Hour * 24 * 20},
		},
	}

	// all ok
	cert := &policiesv1.Cert{
		Duration:   time.Hour * 24 * 36,
		Expiration: "1234",
		Expiry:     time.Hour * 24 * 34,
		Secret:     "test",
		CA:         true,
		Sans:       []string{"a", "b"},
	}
	certmap := map[string]policiesv1.Cert{}
	assert.False(t, haveNewNonCompliantCertificate(instance, "default", certmap))
	certmap["test"] = *cert
	assert.True(t, haveNewNonCompliantCertificate(instance, "default", certmap))
}

func TestProcessPolicies(t *testing.T) {
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-process-policies",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{Duration: time.Hour * 24 * 35},
		},
	}
	r := &CertificatePolicyReconciler{Client: nil, Scheme: nil, Recorder: nil, TargetK8sClient: nil}
	r.handleAddingPolicy(context.TODO(), instance)

	plcToUpdateMap := make(map[string]*policiesv1.CertificatePolicy)
	value := r.ProcessPolicies(context.TODO(), plcToUpdateMap)
	assert.True(t, value)

	_, found := availablePolicies.GetObject("/" + instance.Name)
	assert.True(t, found)
}

func TestParseCertificate(t *testing.T) {
	nstypeMeta := metav1.TypeMeta{
		Kind: "namespace",
	}
	nsobjMeta := metav1.ObjectMeta{
		Name: "default",
	}
	ns := coretypes.Namespace{
		TypeMeta:   nstypeMeta,
		ObjectMeta: nsobjMeta,
	}

	typeMeta := metav1.TypeMeta{
		Kind: "Secret",
	}
	objMeta := metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "default",
	}

	crt := `-----BEGIN CERTIFICATE-----
MIIDRjCCAi4CCQCCORszFlswxjANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB1JlZCBI
YXQxEjAQBgNVBAsMCU9wZW5TaGlmdDERMA8GA1UEAwwIcG9saWNpZXMwHhcNMjAw
MzA1MTQwNjQzWhcNMjAwMzEwMTQwNjQzWjBlMQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB1JlZCBIYXQxEjAQBgNV
BAsMCU9wZW5TaGlmdDERMA8GA1UEAwwIcG9saWNpZXMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC5WwmD2ebCa5hM4yi4TCYFRY/DA4eBLpT5+BqKEL12
inPGSQP37XHF6f6VFqnK/Nr/uzs//24SHDHMUyrFdfYEGFQ9iRcnC4KCYLAeFQ4G
B0DRZSeSzxVVp0sbNMrzoOF5YTuCb+yUr+8Zx5Q7V5JNr/MVRYs33Rj8M+WQ45bb
oy0ehCuvnfvEgzzQY32gkxcB09d6V3sZbth1s88P/pAqcrUQua7XD6eYVGSD8zeY
7Mahqt4lvPiIj6T3qhauH1/sUfl/X98mdabsCkhIgx6fP9Xvx/U/PsjmOBC1ED2E
Jwk5X7U9Nx9tj0KMRHetE5Hn6H/hBqCunWHF18PsDXbfAgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAADBYj6epTrRQ9B+StWEp9x1O+WP0c9BXljW1OtQ/QSVWcIfcdI5
8oGACTPBSyGdHMKJ2zw5bGP8nDwk33d6AcFVsERLHz2VUTajeAFFKSEpVIgqFyDw
ViB36ya7lnJ+RLReJmYI/E55kv/p2x0C0t/BynA0gIFSmIj7IpccimDPJiAyCEtB
uFPO5+jBaPT3/G0z1dDrZZDOxhTSkFuyLTXnaEhIbZQW0Mniq1m5nswOAgfompmA
9MGk0Ozkk5mqeHjfpsrmbyfADasUY2rMc6fwT6UiP80C5m/KEtL8xU92PQDKAhdO
1uwcab91yRPT7mmQ9oeY6k8SMhb1doHA8vc=
-----END CERTIFICATE-----`

	data := make(map[string][]byte)
	data["tls.crt"] = []byte(crt)
	secret := coretypes.Secret{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
		Data:       data,
	}

	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-parse-certificate",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{Duration: time.Hour * 24 * 35},
		},
	}

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()

	r := &CertificatePolicyReconciler{
		Client: nil, Scheme: nil, Recorder: nil,
		TargetK8sClient: simpleClient,
	}

	_, err := simpleClient.CoreV1().Namespaces().Create(context.TODO(), &ns, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Error creating namespace: %s", err)
	}

	s, err := simpleClient.CoreV1().Secrets("default").Create(context.TODO(), &secret, metav1.CreateOptions{})
	assert.NotNil(t, s)
	assert.Nil(t, err)

	if err != nil {
		t.Logf("Error creating a secret: %s", err)
	}

	output, err := json.Marshal(s)
	assert.Nil(t, err)
	t.Log(string(output))

	target := []policiesv1.NonEmptyString{"default"}
	instance.Spec.NamespaceSelector.Include = target

	r.handleAddingPolicy(context.TODO(), instance)

	policy, found := availablePolicies.GetObject(instance.Namespace + "/" + instance.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)

	labelSelector := toLabelSet(instance.Spec.LabelSelector)
	secretList, _ := simpleClient.CoreV1().Secrets("default").List(
		context.TODO(), metav1.ListOptions{
			LabelSelector: labelSelector.String(),
		},
	)
	assert.Len(t, secretList.Items, 1)

	cert, err := parseCertificate(&secretList.Items[0])
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	update, nonCompliant, list := r.checkSecrets(context.TODO(), instance, "default")

	assert.Nil(t, err)
	assert.Equal(t, uint(1), nonCompliant)
	assert.True(t, update)

	message := buildPolicyStatusMessage(list, nonCompliant, "default", instance)
	assert.NotNil(t, message)

	handleRemovingPolicy("foo")

	crt = `-----BEGIN CERTIFICATE-----
MIIC8TCCAdmgAwIBAgIQJHdwEog9UZAGSgMMmG9giDANBgkqhkiG9w0BAQsFADAY
MRYwFAYDVQQDEw10ZWFtcy5pYm0uY29tMB4XDTIwMTAyODE3MjcyMFoXDTIwMTIx
NzE3MjcyMFowGDEWMBQGA1UEAxMNdGVhbXMuaWJtLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMDFIiih358zPhzZ9bcgz8ACdznKogMAey+yWyUX
utYc00HEkq6XeKrOMcWT5bCQ5IqsEkCBQtHUT7kKwyG8yF+4QD33/dsEkqyhfKFI
yxqKxRb0R8ATPnI4dzdmrYEDdvGrI0ddfBAMnWwDv2S7bqADvx2OWkFIRUtCK1fE
l6iPAoSzjNs5wn2F2hNpcty+vQ6dygqjCL2rwzSaR14GZNaAvpKFTNdA8dCkoSZN
LA2nwDQEdszNVQZzRfxaCZc/jwmyglJY1hj2xTZHsw3DpLrWLrBihx4uXHku5aMs
j7JEkRudLvjB6Z9dizEyU1oX6lc3UOd9/qVDDvIOfe4J7A0CAwEAAaM3MDUwDgYD
VR0PAQH/BAQDAgWgMAwGA1UdEwEB/wQCMAAwFQYDVR0RBA4wDIIKKi50ZXN0LmNv
bTANBgkqhkiG9w0BAQsFAAOCAQEAr3cWZowiRt98v7e8c/4CwhhCmT1VPX1i6Nlx
XFBu7PdR/UtY1I/1rT2YbSFNuboYYBcQtziTGkNWyJSw+PBpT0nrUbOLROVRHYmB
14d+qwQ9qDwrRKc8fo7ITKdOLpuQi6LbdYU+jytDCbXWalLjiceLHWYxWPpkgktS
16Xucz9C7/VP9/VhFIU1rhtqpcUFO5BUAuDZ3LrTEE+JAZQuzVvinIwGMBSYxhTp
xUSmOkQ0VchHrQY4a3z4yzgWIdDe34DhonLA1njXcd66kzY5cD1EykmLcIPFLqCx
6IKHLAbLnpMLsbbTXFpp4NiSUssKbPxrJLOMB7xTvwNHnQS/og==
-----END CERTIFICATE-----`

	data["tls.crt"] = []byte(crt)
	objMeta = metav1.ObjectMeta{
		Name:      "bar",
		Namespace: "default",
	}
	secret = coretypes.Secret{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
		Data:       data,
	}

	instance = &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration:          &metav1.Duration{Duration: time.Hour * 24 * 35},
			DisallowedSANPattern: "[\\*]",
			MaxDuration:          &metav1.Duration{Duration: time.Hour * 24 * 375},
		},
	}

	s, err = simpleClient.CoreV1().Secrets("default").Create(context.TODO(), &secret, metav1.CreateOptions{})
	assert.NotNil(t, s)
	assert.Nil(t, err)

	target = []policiesv1.NonEmptyString{"default"}
	instance.Spec.NamespaceSelector.Include = target
	r.handleAddingPolicy(context.TODO(), instance)

	policy, found = availablePolicies.GetObject(instance.Namespace + "/" + instance.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)

	labelSelector = toLabelSet(instance.Spec.LabelSelector)
	secretList, _ = simpleClient.CoreV1().Secrets("default").List(
		context.TODO(), metav1.ListOptions{
			LabelSelector: labelSelector.String(),
		},
	)
	assert.Equal(t, 2, len(secretList.Items))

	update, nonCompliant, list = r.checkSecrets(context.TODO(), instance, "default")

	assert.Nil(t, err)
	assert.Equal(t, uint(2), nonCompliant)
	assert.True(t, update)

	message = buildPolicyStatusMessage(list, nonCompliant, "default", instance)
	assert.NotNil(t, message)
}

func TestMultipleNamespaces(t *testing.T) {
	nstypeMeta := metav1.TypeMeta{
		Kind: "namespace",
	}
	nsobjMeta1 := metav1.ObjectMeta{
		Name: "default1",
	}
	nsobjMeta2 := metav1.ObjectMeta{
		Name: "default2",
	}
	ns1 := coretypes.Namespace{
		TypeMeta:   nstypeMeta,
		ObjectMeta: nsobjMeta1,
	}
	ns2 := coretypes.Namespace{
		TypeMeta:   nstypeMeta,
		ObjectMeta: nsobjMeta2,
	}

	typeMeta := metav1.TypeMeta{
		Kind: "Secret",
	}
	objMeta1 := metav1.ObjectMeta{
		Name:      "foo1",
		Namespace: "default1",
	}
	objMeta2 := metav1.ObjectMeta{
		Name:      "foo2",
		Namespace: "default2",
	}

	crt := `-----BEGIN CERTIFICATE-----
MIIDRjCCAi4CCQCCORszFlswxjANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB1JlZCBI
YXQxEjAQBgNVBAsMCU9wZW5TaGlmdDERMA8GA1UEAwwIcG9saWNpZXMwHhcNMjAw
MzA1MTQwNjQzWhcNMjAwMzEwMTQwNjQzWjBlMQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCTkMxEDAOBgNVBAcMB1JhbGVpZ2gxEDAOBgNVBAoMB1JlZCBIYXQxEjAQBgNV
BAsMCU9wZW5TaGlmdDERMA8GA1UEAwwIcG9saWNpZXMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC5WwmD2ebCa5hM4yi4TCYFRY/DA4eBLpT5+BqKEL12
inPGSQP37XHF6f6VFqnK/Nr/uzs//24SHDHMUyrFdfYEGFQ9iRcnC4KCYLAeFQ4G
B0DRZSeSzxVVp0sbNMrzoOF5YTuCb+yUr+8Zx5Q7V5JNr/MVRYs33Rj8M+WQ45bb
oy0ehCuvnfvEgzzQY32gkxcB09d6V3sZbth1s88P/pAqcrUQua7XD6eYVGSD8zeY
7Mahqt4lvPiIj6T3qhauH1/sUfl/X98mdabsCkhIgx6fP9Xvx/U/PsjmOBC1ED2E
Jwk5X7U9Nx9tj0KMRHetE5Hn6H/hBqCunWHF18PsDXbfAgMBAAEwDQYJKoZIhvcN
AQELBQADggEBAADBYj6epTrRQ9B+StWEp9x1O+WP0c9BXljW1OtQ/QSVWcIfcdI5
8oGACTPBSyGdHMKJ2zw5bGP8nDwk33d6AcFVsERLHz2VUTajeAFFKSEpVIgqFyDw
ViB36ya7lnJ+RLReJmYI/E55kv/p2x0C0t/BynA0gIFSmIj7IpccimDPJiAyCEtB
uFPO5+jBaPT3/G0z1dDrZZDOxhTSkFuyLTXnaEhIbZQW0Mniq1m5nswOAgfompmA
9MGk0Ozkk5mqeHjfpsrmbyfADasUY2rMc6fwT6UiP80C5m/KEtL8xU92PQDKAhdO
1uwcab91yRPT7mmQ9oeY6k8SMhb1doHA8vc=
-----END CERTIFICATE-----`

	data := make(map[string][]byte)
	data["tls.crt"] = []byte(crt)
	secret1 := coretypes.Secret{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta1,
		Data:       data,
	}
	secret2 := coretypes.Secret{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta2,
		Data:       data,
	}

	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-multiple-namespaces",
			Namespace: "default2",
		},
		Spec: policiesv1.CertificatePolicySpec{
			NamespaceSelector: policiesv1.Target{
				Include: []policiesv1.NonEmptyString{"def*"},
			},
			MinDuration: &metav1.Duration{Duration: time.Hour * 24 * 35},
		},
	}

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()

	r := &CertificatePolicyReconciler{
		Client: nil, Scheme: nil, Recorder: nil,
		TargetK8sClient: simpleClient,
	}

	_, err := simpleClient.CoreV1().Namespaces().Create(context.TODO(), &ns1, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Error creating namespace 1: %s", err)
	}

	_, err = simpleClient.CoreV1().Namespaces().Create(context.TODO(), &ns2, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Error creating namespace 2: %s", err)
	}

	s, err := simpleClient.CoreV1().Secrets("default1").Create(context.TODO(), &secret1, metav1.CreateOptions{})
	assert.NotNil(t, s)
	assert.Nil(t, err)

	if err != nil {
		t.Logf("Error creating secret 1: %s", err)
	}

	s, err = simpleClient.CoreV1().Secrets("default2").Create(context.TODO(), &secret2, metav1.CreateOptions{})
	assert.NotNil(t, s)
	assert.Nil(t, err)

	if err != nil {
		t.Logf("Error creating secret 2: %s", err)
	}

	target := []policiesv1.NonEmptyString{"def*"}
	instance.Spec.NamespaceSelector.Include = target

	r.handleAddingPolicy(context.TODO(), instance)

	policy, found := availablePolicies.GetObject(instance.Namespace + "/" + instance.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)

	plcToUpdateMap := make(map[string]*policiesv1.CertificatePolicy)

	stateChange := r.ProcessPolicies(context.TODO(), plcToUpdateMap)
	assert.True(t, stateChange)

	message := convertPolicyStatusToString(instance, DefaultDuration)
	assert.NotNil(t, message)
	t.Logf("Message created for policy: %s", message)
	first := strings.Index(message, "default1")
	second := strings.Index(message, "default2")
	assert.Less(t, first, second)

	handleRemovingPolicy("foo")
}
