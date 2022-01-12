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
package certificatepolicy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	coretypes "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	testclient "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policiesv1 "github.com/stolostron/cert-policy-controller/pkg/apis/policies/v1"
	"github.com/stolostron/cert-policy-controller/pkg/common"
)

var mgr manager.Manager
var err error

func TestReconcile(t *testing.T) {
	var (
		name      = "foo"
		namespace = "default"
	)
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration:          &metav1.Duration{time.Hour * 24 * 35},
			AllowedSANPattern:    "[[:alpha:]]",
			DisallowedSANPattern: "[^\\*]",
			MinCADuration:        &metav1.Duration{time.Hour * 24 * 35},
			MaxCADuration:        &metav1.Duration{time.Hour * 24 * 35},
			MaxDuration:          &metav1.Duration{time.Hour * 24 * 35},
		},
	}

	// Objects to track in the fake client.
	objs := []runtime.Object{instance}
	// Register operator types with the runtime scheme.
	s := scheme.Scheme
	s.AddKnownTypes(policiesv1.SchemeGroupVersion, instance)

	// Create a fake client to mock API calls.
	cl := fake.NewFakeClient(objs...)
	// Create a ReconcileCertificatePolicy object with the scheme and fake client
	r := &ReconcileCertificatePolicy{client: cl, scheme: s, recorder: nil}

	// Mock request to simulate Reconcile() being called on an event for a
	// watched resource .
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()
	common.Initialize(&simpleClient, nil)
	res, err := r.Reconcile(req)
	if err != nil {
		t.Fatalf("reconcile: (%v)", err)
	}
	t.Log(res)
}

func TestPeriodicallyExecCertificatePolicies(t *testing.T) {
	var (
		name      = "foo"
		namespace = "default"
	)
	var typeMeta = metav1.TypeMeta{
		Kind: "namespace",
	}
	var objMeta = metav1.ObjectMeta{
		Name: "default",
	}
	var ns = coretypes.Namespace{
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
			MinDuration: &metav1.Duration{time.Hour * 24 * 35},
		},
	}

	// Objects to track in the fake client.
	objs := []runtime.Object{instance}
	// Register operator types with the runtime scheme.
	s := scheme.Scheme
	s.AddKnownTypes(policiesv1.SchemeGroupVersion, instance)

	// Create a fake client to mock API calls.
	cl := fake.NewFakeClient(objs...)

	// Create a ReconcileCertificatePolicy object with the scheme and fake client.
	r := &ReconcileCertificatePolicy{client: cl, scheme: s, recorder: nil}
	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()
	simpleClient.CoreV1().Namespaces().Create(&ns)
	common.Initialize(&simpleClient, nil)
	res, err := r.Reconcile(req)
	if err != nil {
		t.Fatalf("reconcile: (%v)", err)
	}
	t.Log(res)
	var target = []string{"default"}
	certPolicy.Spec.NamespaceSelector.Include = target
	handleAddingPolicy(&certPolicy)
	PeriodicallyExecCertificatePolicies(1, false)
	policy, found := availablePolicies.GetObject(certPolicy.Namespace + "/" + certPolicy.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)
}

func TestCheckComplianceBasedOnDetails(t *testing.T) {
	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()
	common.Initialize(&simpleClient, nil)
	var certPolicy = policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		}}

	var policies = map[string]*policiesv1.CertificatePolicy{}
	policies["policy1"] = &certPolicy

	checkComplianceBasedOnDetails(&certPolicy)
}

func TestEnsureDefaultLabel(t *testing.T) {
	updateNeeded := ensureDefaultLabel(&certPolicy)
	assert.True(t, updateNeeded)

	var labels1 = map[string]string{}
	labels1["category"] = grcCategory
	certPolicy.Labels = labels1
	updateNeeded = ensureDefaultLabel(&certPolicy)
	assert.False(t, updateNeeded)

	var labels2 = map[string]string{}
	labels2["category"] = "foo"
	certPolicy.Labels = labels2
	updateNeeded = ensureDefaultLabel(&certPolicy)
	assert.True(t, updateNeeded)

	var labels3 = map[string]string{}
	labels3["foo"] = grcCategory
	certPolicy.Labels = labels3
	updateNeeded = ensureDefaultLabel(&certPolicy)
	assert.True(t, updateNeeded)
}

func TestCheckComplianceChangeBasedOnDetails(t *testing.T) {
	var certPolicy = policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		}}
	var flag = checkComplianceChangeBasedOnDetails(&certPolicy)
	assert.False(t, flag)
}

func TestCreateParentPolicy(t *testing.T) {
	var ownerReference = metav1.OwnerReference{
		Name: "foo",
	}
	var ownerReferences = []metav1.OwnerReference{}
	ownerReferences = append(ownerReferences, ownerReference)
	certPolicy.OwnerReferences = ownerReferences

	policy := createParentPolicy(&certPolicy)
	assert.NotNil(t, policy)
	createParentPolicyEvent(&certPolicy)
}

func TestHandleAddingPolicy(t *testing.T) {
	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()
	var typeMeta = metav1.TypeMeta{
		Kind: "namespace",
	}
	var objMeta = metav1.ObjectMeta{
		Name: "default",
	}
	var ns = coretypes.Namespace{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
	}
	simpleClient.CoreV1().Namespaces().Create(&ns)
	common.Initialize(&simpleClient, nil)
	handleAddingPolicy(&certPolicy)
	policy, found := availablePolicies.GetObject(certPolicy.Namespace + "/" + certPolicy.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)
	handleRemovingPolicy(certPolicy.Name)
}

func TestPrintMap(t *testing.T) {
	var policies = map[string]*policiesv1.CertificatePolicy{}
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
			MinDuration:          &metav1.Duration{time.Hour * 24 * 35},
			AllowedSANPattern:    "allowed",
			DisallowedSANPattern: "disallowed",
		},
	}

	pattern := getPatternsUsed(instance)
	assert.True(t, pattern == fmt.Sprintf("Allowed: %s Disallowed: %s", "allowed", "disallowed"))
}

func TestIsCertificateCompliant(t *testing.T) {
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration:          &metav1.Duration{time.Hour * 24 * 10},
			AllowedSANPattern:    "[ab]",
			DisallowedSANPattern: "[\\*]",
			MaxCADuration:        &metav1.Duration{time.Hour * 24 * 100},
			MaxDuration:          &metav1.Duration{time.Hour * 24 * 50},
			MinCADuration:        &metav1.Duration{time.Hour * 24 * 20},
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
			MinDuration:          &metav1.Duration{time.Hour * 24 * 10},
			AllowedSANPattern:    "[ab]",
			DisallowedSANPattern: "[\\*]",
			MaxCADuration:        &metav1.Duration{time.Hour * 24 * 100},
			MaxDuration:          &metav1.Duration{time.Hour * 24 * 50},
			MinCADuration:        &metav1.Duration{time.Hour * 24 * 20},
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
	var certmap = map[string]policiesv1.Cert{}
	assert.False(t, haveNewNonCompliantCertificate(instance, "default", certmap))
	certmap["test"] = *cert
	assert.True(t, haveNewNonCompliantCertificate(instance, "default", certmap))
}

func TestProcessPolicies(t *testing.T) {
	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{time.Hour * 24 * 35},
		},
	}
	handleAddingPolicy(instance)
	plcToUpdateMap := make(map[string]*policiesv1.CertificatePolicy)
	value := ProcessPolicies(plcToUpdateMap)
	assert.True(t, value)

	_, found := availablePolicies.GetObject("/foo")
	assert.True(t, found)
}

func TestParseCertificate(t *testing.T) {

	var nstypeMeta = metav1.TypeMeta{
		Kind: "namespace",
	}
	var nsobjMeta = metav1.ObjectMeta{
		Name: "default",
	}
	var ns = coretypes.Namespace{
		TypeMeta:   nstypeMeta,
		ObjectMeta: nsobjMeta,
	}

	var typeMeta = metav1.TypeMeta{
		Kind: "Secret",
	}
	var objMeta = metav1.ObjectMeta{
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

	//crt := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURSakNDQWk0Q0NRQ0NPUnN6Rmxzd3hqQU5CZ2txaGtpRzl3MEJBUXNGQURCbE1Rc3dDUVlEVlFRR0V3SlYKVXpFTE1Ba0dBMVVFQ0F3Q1RrTXhFREFPQmdOVkJBY01CMUpoYkdWcFoyZ3hFREFPQmdOVkJBb01CMUpsWkNCSQpZWFF4RWpBUUJnTlZCQXNNQ1U5d1pXNVRhR2xtZERFUk1BOEdBMVVFQXd3SWNHOXNhV05wWlhNd0hoY05NakF3Ck16QTFNVFF3TmpReldoY05NakF3TXpFd01UUXdOalF6V2pCbE1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUUKQ0F3Q1RrTXhFREFPQmdOVkJBY01CMUpoYkdWcFoyZ3hFREFPQmdOVkJBb01CMUpsWkNCSVlYUXhFakFRQmdOVgpCQXNNQ1U5d1pXNVRhR2xtZERFUk1BOEdBMVVFQXd3SWNHOXNhV05wWlhNd2dnRWlNQTBHQ1NxR1NJYjNEUUVCCkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDNVd3bUQyZWJDYTVoTTR5aTRUQ1lGUlkvREE0ZUJMcFQ1K0JxS0VMMTIKaW5QR1NRUDM3WEhGNmY2VkZxbksvTnIvdXpzLy8yNFNIREhNVXlyRmRmWUVHRlE5aVJjbkM0S0NZTEFlRlE0RwpCMERSWlNlU3p4VlZwMHNiTk1yem9PRjVZVHVDYit5VXIrOFp4NVE3VjVKTnIvTVZSWXMzM1JqOE0rV1E0NWJiCm95MGVoQ3V2bmZ2RWd6elFZMzJna3hjQjA5ZDZWM3NaYnRoMXM4OFAvcEFxY3JVUXVhN1hENmVZVkdTRDh6ZVkKN01haHF0NGx2UGlJajZUM3FoYXVIMS9zVWZsL1g5OG1kYWJzQ2toSWd4NmZQOVh2eC9VL1Bzam1PQkMxRUQyRQpKd2s1WDdVOU54OXRqMEtNUkhldEU1SG42SC9oQnFDdW5XSEYxOFBzRFhiZkFnTUJBQUV3RFFZSktvWklodmNOCkFRRUxCUUFEZ2dFQkFBREJZajZlcFRyUlE5QitTdFdFcDl4MU8rV1AwYzlCWGxqVzFPdFEvUVNWV2NJZmNkSTUKOG9HQUNUUEJTeUdkSE1LSjJ6dzViR1A4bkR3azMzZDZBY0ZWc0VSTEh6MlZVVGFqZUFGRktTRXBWSWdxRnlEdwpWaUIzNnlhN2xuSitSTFJlSm1ZSS9FNTVrdi9wMngwQzB0L0J5bkEwZ0lGU21JajdJcGNjaW1EUEppQXlDRXRCCnVGUE81K2pCYVBUMy9HMHoxZERyWlpET3hoVFNrRnV5TFRYbmFFaEliWlFXME1uaXExbTVuc3dPQWdmb21wbUEKOU1HazBPemtrNW1xZUhqZnBzcm1ieWZBRGFzVVkyck1jNmZ3VDZVaVA4MEM1bS9LRXRMOHhVOTJQUURLQWhkTwoxdXdjYWI5MXlSUFQ3bW1ROW9lWTZrOFNNaGIxZG9IQTh2Yz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
	data := make(map[string][]byte)
	data["tls.crt"] = []byte(crt)
	var secret = coretypes.Secret{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
		Data:       data,
	}

	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: policiesv1.CertificatePolicySpec{
			MinDuration: &metav1.Duration{time.Hour * 24 * 35},
		},
	}

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()

	simpleClient.CoreV1().Namespaces().Create(&ns)
	s, err := simpleClient.CoreV1().Secrets("default").Create(&secret)
	assert.NotNil(t, s)
	assert.Nil(t, err)
	if err != nil {
		t.Logf("Error creating a secret: %s", err)
	}

	output, _ := json.Marshal(s)
	t.Log(string(output))

	var target = []string{"default"}
	instance.Spec.NamespaceSelector.Include = target
	common.Initialize(&simpleClient, nil)
	handleAddingPolicy(instance)
	policy, found := availablePolicies.GetObject(certPolicy.Namespace + "/" + certPolicy.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)

	secretList, _ := (*common.KubeClient).CoreV1().Secrets("default").List(metav1.ListOptions{LabelSelector: labels.Set(instance.Spec.LabelSelector).String()})
	assert.True(t, len(secretList.Items) == 1)

	cert, err := parseCertificate(&secretList.Items[0])
	assert.Nil(t, err)
	assert.NotNil(t, cert)

	update, nonCompliant, list := checkSecrets(instance, "default")
	assert.Nil(t, err)
	t.Logf("Count of secrets found: %d", nonCompliant)
	assert.True(t, nonCompliant == 1)
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
			MinDuration:          &metav1.Duration{time.Hour * 24 * 35},
			DisallowedSANPattern: "[\\*]",
			MaxDuration:          &metav1.Duration{time.Hour * 24 * 375},
		},
	}

	s, err = simpleClient.CoreV1().Secrets("default").Create(&secret)
	assert.NotNil(t, s)
	assert.Nil(t, err)

	target = []string{"default"}
	instance.Spec.NamespaceSelector.Include = target
	handleAddingPolicy(instance)
	policy, found = availablePolicies.GetObject(certPolicy.Namespace + "/" + certPolicy.Name)
	assert.True(t, found)
	assert.NotNil(t, policy)

	secretList, _ = (*common.KubeClient).CoreV1().Secrets("default").List(metav1.ListOptions{LabelSelector: labels.Set(instance.Spec.LabelSelector).String()})
	assert.True(t, len(secretList.Items) == 2)

	update, nonCompliant, list = checkSecrets(instance, "default")
	assert.Nil(t, err)
	t.Logf("Count of secrets found: %d", nonCompliant)
	assert.True(t, nonCompliant == 2)
	assert.True(t, update)

	message = buildPolicyStatusMessage(list, nonCompliant, "default", instance)
	assert.NotNil(t, message)
}

func TestMultipleNamespaces(t *testing.T) {

	var nstypeMeta = metav1.TypeMeta{
		Kind: "namespace",
	}
	var nsobjMeta1 = metav1.ObjectMeta{
		Name: "default1",
	}
	var nsobjMeta2 = metav1.ObjectMeta{
		Name: "default2",
	}
	var ns1 = coretypes.Namespace{
		TypeMeta:   nstypeMeta,
		ObjectMeta: nsobjMeta1,
	}
	var ns2 = coretypes.Namespace{
		TypeMeta:   nstypeMeta,
		ObjectMeta: nsobjMeta2,
	}

	var typeMeta = metav1.TypeMeta{
		Kind: "Secret",
	}
	var objMeta1 = metav1.ObjectMeta{
		Name:      "foo1",
		Namespace: "default1",
	}
	var objMeta2 = metav1.ObjectMeta{
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
	var secret1 = coretypes.Secret{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta1,
		Data:       data,
	}
	var secret2 = coretypes.Secret{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta2,
		Data:       data,
	}

	instance := &policiesv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default2",
		},
		Spec: policiesv1.CertificatePolicySpec{
			NamespaceSelector: policiesv1.Target{
				Include: []string{"def*"},
			},
			MinDuration: &metav1.Duration{time.Hour * 24 * 35},
		},
	}

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()

	simpleClient.CoreV1().Namespaces().Create(&ns1)
	simpleClient.CoreV1().Namespaces().Create(&ns2)
	s, err := simpleClient.CoreV1().Secrets("default1").Create(&secret1)
	assert.NotNil(t, s)
	assert.Nil(t, err)
	if err != nil {
		t.Logf("Error creating secret 1: %s", err)
	}
	s, err = simpleClient.CoreV1().Secrets("default2").Create(&secret2)
	assert.NotNil(t, s)
	assert.Nil(t, err)
	if err != nil {
		t.Logf("Error creating secret 2: %s", err)
	}

	target := []string{"def*"}
	instance.Spec.NamespaceSelector.Include = target
	common.Initialize(&simpleClient, nil)
	handleAddingPolicy(instance)
	policy, found := availablePolicies.GetObject("default1/foo")
	assert.True(t, found)
	assert.NotNil(t, policy)

	plcToUpdateMap := make(map[string]*policiesv1.CertificatePolicy)

	stateChange := ProcessPolicies(plcToUpdateMap)
	assert.True(t, stateChange)

	message := convertPolicyStatusToString(instance, DefaultDuration)
	assert.NotNil(t, message)
	t.Logf("Message created for policy: %s", message)
	first := strings.Index(message, "default1")
	second := strings.Index(message, "default2")
	assert.True(t, first < second)

	handleRemovingPolicy("foo")

}
