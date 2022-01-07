// Copyright Contributors to the Open Cluster Management project

package certificatepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	policyv1 "github.com/stolostron/cert-policy-controller/apis/policy/v1"
	//+kubebuilder:scaffold:imports
)

var certPolicy = policyv1.CertificatePolicy{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "foo",
		Namespace: "default",
	}}

var testEnv *envtest.Environment

func TestMain(m *testing.M) {
	RegisterFailHandler(ginkgo.Fail)

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = policyv1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	code := m.Run()

	err = testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
	os.Exit(code)
}
