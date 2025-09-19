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

	policiesv1 "open-cluster-management.io/cert-policy-controller/api/v1"
)

func TestPeriodicallyExecCertificatePolicies(t *testing.T) {
	ns := &coretypes.Namespace{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "namespace",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	instance := &policiesv1.CertificatePolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CertificatePolicy",
			APIVersion: policiesv1.GroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{Duration: time.Hour * 24 * 35},
		},
	}

	// Objects to track in the fake client.
	objs := []runtime.Object{ns, instance}
	// Register operator types with the runtime scheme.
	s := runtime.NewScheme()
	err := scheme.AddToScheme(s)
	assert.NoError(t, err)
	err = policiesv1.AddToScheme(s)
	assert.NoError(t, err)

	// Create a fake client to mock API calls.
	cl := fake.NewClientBuilder().WithStatusSubresource(instance).WithScheme(s).WithRuntimeObjects(objs...)

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()
	// Create a ReconcileCertificatePolicy object with the scheme and fake client.
	r := &CertificatePolicyReconciler{Client: cl.Build(), Scheme: s, Recorder: nil, TargetK8sClient: simpleClient}

	_, err = r.TargetK8sClient.CoreV1().Namespaces().Create(t.Context(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Error creating namespace: %s", err)
		assert.NoError(t, err)
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

	for _, test := range tests {
		t.Run(
			test.description,
			func(t *testing.T) {
				certPolicy := policiesv1.CertificatePolicy{}

				err := r.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "foo"}, &certPolicy)
				assert.NoError(t, err)

				certPolicy.Spec.NamespaceSelector.Include = []policiesv1.NonEmptyString{test.namespaceSelector}

				err = r.Update(t.Context(), &certPolicy)
				assert.NoError(t, err)

				r.PeriodicallyExecCertificatePolicies(t.Context(), 1, false)

				certPolicy = policiesv1.CertificatePolicy{}

				err = r.Get(t.Context(), types.NamespacedName{Namespace: "default", Name: "foo"}, &certPolicy)
				assert.NoError(t, err)

				assert.Equal(t, test.complianceState, certPolicy.Status.ComplianceState)
				assert.Equal(t, test.expectedMsg, certPolicy.Status.CompliancyDetails[test.cacheNamespace].Message)
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

	checkComplianceBasedOnDetails(&certPolicy)
}

func TestSendComplianceEvent(t *testing.T) {
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

	// Create a fake client to mock API calls.
	s := runtime.NewScheme()
	err := scheme.AddToScheme(s)
	assert.NoError(t, err)
	err = policiesv1.AddToScheme(s)
	assert.NoError(t, err)

	objs := []runtime.Object{certPolicy}
	cl := fake.NewClientBuilder().WithScheme(s).WithRuntimeObjects(objs...).Build()

	r := &CertificatePolicyReconciler{Client: cl, Scheme: s, Recorder: nil, TargetK8sClient: nil}

	err = r.sendComplianceEvent(t.Context(), certPolicy, time.Now())
	assert.NoError(t, err)
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

func createNamespace(t *testing.T, simpleClient kubernetes.Interface, namespace string) {
	t.Helper()

	nstypeMeta := metav1.TypeMeta{
		Kind: "namespace",
	}
	nsobjMeta := metav1.ObjectMeta{
		Name: namespace,
	}
	ns := coretypes.Namespace{
		TypeMeta:   nstypeMeta,
		ObjectMeta: nsobjMeta,
	}

	_, err := simpleClient.CoreV1().Namespaces().Create(t.Context(), &ns, metav1.CreateOptions{})
	if err != nil {
		t.Logf("Error creating namespace: %s", err)
	}
}

func createExpiredCertSecret(t *testing.T, simpleClient kubernetes.Interface,
	namespace string, name string, labels map[string]string,
) {
	t.Helper()

	typeMeta := metav1.TypeMeta{
		Kind: "Secret",
	}
	objMeta := metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
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

	if labels != nil {
		secret.ObjectMeta.Labels = labels
	}

	s, err := simpleClient.CoreV1().Secrets(namespace).Create(t.Context(), &secret, metav1.CreateOptions{})
	assert.NotNil(t, s)
	assert.NoError(t, err)
}

func TestProcessPolicies(t *testing.T) {
	policies := &policiesv1.CertificatePolicyList{
		Items: []policiesv1.CertificatePolicy{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "foo-process-policies",
					Namespace: "default",
				},
				Spec: policiesv1.CertificatePolicySpec{
					MinDuration: &metav1.Duration{Duration: time.Hour * 24 * 35},
				},
			},
		},
	}

	r := &CertificatePolicyReconciler{Client: nil, Scheme: nil, Recorder: nil, TargetK8sClient: nil}

	updatedPolicies := r.ProcessPolicies(t.Context(), policies)

	assert.Len(t, updatedPolicies, 1)
}

func TestParseCertificate(t *testing.T) {
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

	createNamespace(t, simpleClient, "default")

	createExpiredCertSecret(t, simpleClient, "default", "foo", map[string]string{})

	target := []policiesv1.NonEmptyString{"default"}
	instance.Spec.NamespaceSelector.Include = target

	labelSelector := toLabelSet(instance.Spec.LabelSelector)
	secretList, _ := simpleClient.CoreV1().Secrets("default").List(
		t.Context(), metav1.ListOptions{
			LabelSelector: labelSelector.String(),
		},
	)
	assert.Len(t, secretList.Items, 1)

	cert := parseCertificate(&secretList.Items[0])
	assert.NotNil(t, cert)

	update, nonCompliant, list := r.checkSecrets(t.Context(), instance, "default")

	assert.Equal(t, uint(1), nonCompliant)
	assert.True(t, update)

	message := buildPolicyStatusMessage(list, nonCompliant, "default", instance)
	assert.NotNil(t, message)

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

	createExpiredCertSecret(t, simpleClient, "default", "bar", map[string]string{})

	target = []policiesv1.NonEmptyString{"default"}
	instance.Spec.NamespaceSelector.Include = target

	labelSelector = toLabelSet(instance.Spec.LabelSelector)
	secretList, _ = simpleClient.CoreV1().Secrets("default").List(
		t.Context(), metav1.ListOptions{
			LabelSelector: labelSelector.String(),
		},
	)
	assert.Len(t, secretList.Items, 2)

	update, nonCompliant, list = r.checkSecrets(t.Context(), instance, "default")

	assert.Equal(t, uint(2), nonCompliant)
	assert.True(t, update)

	message = buildPolicyStatusMessage(list, nonCompliant, "default", instance)
	assert.NotNil(t, message)
}

func TestMultipleNamespaces(t *testing.T) {
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

	createNamespace(t, simpleClient, "default1")
	createNamespace(t, simpleClient, "default2")
	createExpiredCertSecret(t, simpleClient, "default1", "foo1", map[string]string{})
	createExpiredCertSecret(t, simpleClient, "default2", "foo2", map[string]string{})

	target := []policiesv1.NonEmptyString{"def*"}
	instance.Spec.NamespaceSelector.Include = target

	policies := &policiesv1.CertificatePolicyList{
		Items: []policiesv1.CertificatePolicy{*instance},
	}

	updatedPolicies := r.ProcessPolicies(t.Context(), policies)
	assert.Len(t, updatedPolicies, 1)

	message := convertPolicyStatusToString(updatedPolicies[0], DefaultDuration)
	assert.NotNil(t, message)
	t.Logf("Message created for policy: %s", message)
	first := strings.Index(message, "default1")
	second := strings.Index(message, "default2")
	assert.Less(t, first, second)
}

func TestSecretLabelSelection(t *testing.T) {
	selector := make(map[string]policiesv1.NonEmptyString)
	selector["selection"] = "match"
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-multiple-namespaces",
			Namespace: "default2",
		},
		Spec: policiesv1.CertificatePolicySpec{
			NamespaceSelector: policiesv1.Target{
				Include: []policiesv1.NonEmptyString{"def*"},
			},
			MinDuration:   &metav1.Duration{Duration: time.Hour * 24 * 35},
			LabelSelector: selector,
		},
	}

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()

	r := &CertificatePolicyReconciler{
		Client: nil, Scheme: nil, Recorder: nil,
		TargetK8sClient: simpleClient,
	}

	createNamespace(t, simpleClient, "default1")
	createNamespace(t, simpleClient, "default2")
	createExpiredCertSecret(t, simpleClient, "default1", "foo1", map[string]string{})

	labels := make(map[string]string)
	labels["selection"] = "match"
	createExpiredCertSecret(t, simpleClient, "default2", "foo2", labels)

	target := []policiesv1.NonEmptyString{"def*"}
	instance.Spec.NamespaceSelector.Include = target

	policies := &policiesv1.CertificatePolicyList{
		Items: []policiesv1.CertificatePolicy{*instance},
	}

	updatedPolicies := r.ProcessPolicies(t.Context(), policies)
	assert.Len(t, updatedPolicies, 1)

	// With the label selector only the secret default2 is matched
	message := convertPolicyStatusToString(updatedPolicies[0], DefaultDuration)
	assert.NotNil(t, message)
	t.Logf("Message created for policy: %s", message)
	first := strings.Index(message, "default1")
	assert.Equal(t, -1, first)

	second := strings.Index(message, "default2")
	assert.Positive(t, second)
}
