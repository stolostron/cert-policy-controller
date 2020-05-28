// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.

package grcpolicy

import (
	"testing"
	"time"

	"github.com/onsi/gomega"
	policyv1 "github.com/open-cluster-management/cert-policy-controller/pkg/apis/policies/v1"
	"golang.org/x/net/context"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var c client.Client

var expectedRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "foo", Namespace: "default"}}
var depKey = types.NamespacedName{Name: "foo", Namespace: "default"}

const timeout = time.Second * 65

func TestReconcile(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	instance := createPolicy("foo", "default", policyv1.Inform)
	//instance := &policyv1.CertificatePolicy{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"}}

	// Setup the Manager and Controller.  Wrap the Controller Reconcile function so it writes each request to a
	// channel when it is finished.
	mgr, err := manager.New(cfg, manager.Options{})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	c = mgr.GetClient()

	recFn, requests := SetupTestReconcile(newReconciler(mgr))
	g.Expect(add(mgr, recFn)).NotTo(gomega.HaveOccurred())

	stopMgr, mgrStopped := StartTestManager(mgr, g)

	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

	// Create the GRCPolicy object and expect the Reconcile and policy to be created
	err = c.Create(context.TODO(), instance)
	// The instance object may not be a valid object because it might be missing some required fields.
	// Please modify the instance object by adding required fields and then remove the following if statement.
	if apierrors.IsInvalid(err) {
		t.Logf("failed to create object, got an invalid object error: %v", err)
		return
	}

	g.Expect(err).NotTo(gomega.HaveOccurred())

	//defer c.Delete(context.TODO(), instance)
	//g.Eventually(requests, timeout).Should(gomega.Receive(gomega.Equal(expectedRequest)))

	secret, err := createExpiredCertificate(c)
	if err != nil {
		t.Logf("failed to create certificate secret, got an error: %v", err)
	}

	g.Eventually(func() error { return c.Get(context.TODO(), depKey, instance) }, timeout).
		Should(gomega.Succeed())

	//g.Expect(c.Delete(context.TODO(), instance)).NotTo(gomega.HaveOccurred())
	//g.Eventually(requests, timeout).Should(gomega.Receive(gomega.Equal(expectedRequest)))

	t.Logf("failed to create object, got an invalid object error: %v", requests)
	t.Logf("failed to create object, got an invalid object error: %v", secret)
	t.Logf("failed to create object, got an invalid object error: %v", instance.Status.ComplianceState)

	//if secret != nil {
	//	c.Delete(context.TODO(), secret)
	//}
}

func createPolicy(policyName, PolicyNamespace string, remediation policyv1.RemediationAction) (plc *policyv1.CertificatePolicy) {
	duration := &metav1.Duration{Duration: time.Hour * 24 * 120}
	return &policyv1.CertificatePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName,
			Namespace: PolicyNamespace,
		},
		Spec: policyv1.CertificatePolicySpec{
			RemediationAction: remediation,
			NamespaceSelector: policyv1.Target{
				Include: []string{"default"},
				Exclude: []string{"kube*"},
			},
			MinDuration: duration,
		},
	}
}

func createPod(podName, PodNamespace string) (myPod *corev1.Pod) {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: PodNamespace}}

}

func createDeployment(depName, depNamespace string) (myDeployment *appsv1.Deployment) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      depName + "-deployment",
			Namespace: depNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"deployment": depName + "-deployment"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"deployment": depName + "-deployment"}},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx",
						},
					},
				},
			},
		},
	}
	return deployment
}

func createNamespace(nsName string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: nsName,
	},
	}
}

func createExpiredCertificate(client client.Client) (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "expired-cert-secret",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey: []byte(`-----BEGIN CERTIFICATE-----
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
			-----END CERTIFICATE-----`),
			corev1.TLSPrivateKeyKey: []byte(`-----BEGIN PRIVATE KEY-----
			MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5WwmD2ebCa5hM
			4yi4TCYFRY/DA4eBLpT5+BqKEL12inPGSQP37XHF6f6VFqnK/Nr/uzs//24SHDHM
			UyrFdfYEGFQ9iRcnC4KCYLAeFQ4GB0DRZSeSzxVVp0sbNMrzoOF5YTuCb+yUr+8Z
			x5Q7V5JNr/MVRYs33Rj8M+WQ45bboy0ehCuvnfvEgzzQY32gkxcB09d6V3sZbth1
			s88P/pAqcrUQua7XD6eYVGSD8zeY7Mahqt4lvPiIj6T3qhauH1/sUfl/X98mdabs
			CkhIgx6fP9Xvx/U/PsjmOBC1ED2EJwk5X7U9Nx9tj0KMRHetE5Hn6H/hBqCunWHF
			18PsDXbfAgMBAAECggEACMsFz4h1xwFdr0ATfXK3VwauxDyVoA46qQUZFTWoF0iI
			J37tPkS4YgAwwJfbpDKMnRcfv3B5o0hNIHlNjSKEcjtJO8YWIBcOsOqvUC4FhUmw
			zH40+2TxiSevi3HcsuQN7jkrnot6uK8D88AhCxOjcCYJrReofBT0C3rWyCHT1UV6
			wnnOvx1KE8/3HjUsKHg3u9PpFe3dSptzylRnWfhJMJfWDDnNT5TbzKmLn1tgz0LY
			LZUMC1SzvfA2U2xjwnm2UK8p/gcU4z19RWqOZC0ba67SDICojRpWt9eIeE0KA2Fg
			j7LvFh6kJcMkCvjNYdfSCmxwbIkrKekFfo8oAh3GqQKBgQDawFS8Uqq/LrKINVnf
			ZkYzYax0biyMJjXUUUApjJYYAeBgJKFXbSuR5nDE07qF3HsJihEjaQZiTvj/0+G1
			Mgnk1NlXB4bkDz0p39f+f7xYWS/vL4/smoMTDwyDi7dyrNDj6Qo1dSVNkxNX8ncg
			MIvYF8MBouq5/+pzII9sLdIb5QKBgQDY6vFUxe7GQIF/pU5s70GXdLTwcPU6gDZu
			THQqthP5R7HQ11t87gkGViHZv0o4JbSQWHeWo/MFAQYID+EmigsKam6dmB6RAhw0
			BLeyi3ko2pYj53AFiL8Eyo0Zu3YUgJlCSrGoNPKXHFVlhwp+DTAKpwS71hARk227
			YaBmygZDcwKBgH4lhXfocCC57CiSI5apovgEbm/iDPxxGH+sr0SGlxOXGW44EXaa
			NRL5AbTvqFODdsxke0ehTBYrFnppFHLqPTxh5kfCxm4Dv7DDLgrMXK/SFstm8Sdv
			XwEBn6TIUGzn7bpQbBuxx2Y512DTKRE+DZb69PCfo57JTsk/UJYAwnZlAoGAMkAK
			9AZ+T/L1jOpwho/OdBWXLPQd+xVkhpyzdImFiwPuz2B0UzaZZJxjbxv/R46Ei8PS
			wFTuoUQhb5CuKc1kzV7mjR+GRTVl7y8Alx30TWCF039z1fRdu/BoS4O/0PQRjOfc
			zAioAhWQOtrTtWu8q1sRn6nxQwESNIxjKiy20r0CgYEAmjGpS2LuDF4XfnbnWcoV
			VFnAaRh5iYS3yQi0EnIdYIhddMLwomX0b17sTnE0c7NbKGH3BN3q/+NHBWXYxfu3
			pJc3Pjo0TdUH+bdQ/nLywepyXZ2RUHF3VMobwccY0SDtzEfQTQhCfedcz/lVEpqC
			hyuKbngkZvbKBU9ulI8a8zw=
			-----END PRIVATE KEY-----`),
		},
	}
	err := c.Create(context.TODO(), secret)
	// The instance object may not be a valid object because it might be missing some required fields.
	// Please modify the instance object by adding required fields and then remove the following if statement.
	if apierrors.IsInvalid(err) {
		return nil, err
	}
	return secret, err
}
