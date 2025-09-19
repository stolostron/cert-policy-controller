// Copyright (c) 2020 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package e2e

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

var (
	testNamespace         string
	gvrPolicy             schema.GroupVersionResource
	defaultTimeoutSeconds int
	kubeconfigManaged     string
	clientManaged         kubernetes.Interface
	clientManagedDynamic  dynamic.Interface
	gvrCertPolicy         schema.GroupVersionResource
	gvrNS                 schema.GroupVersionResource
	gvrSecret             schema.GroupVersionResource

	defaultImageRegistry string
)

func TestE2e(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certificate policy controller e2e Suite")
}

func init() {
	klog.SetOutput(GinkgoWriter)
	klog.InitFlags(nil)
	flag.StringVar(&kubeconfigManaged, "kubeconfig_managed", "../../kubeconfig_managed_e2e",
		"Location of the kubeconfig to use; defaults to current kubeconfig if set to an empty string")
}

var _ = BeforeSuite(func() {
	By("Setup Hub client")
	gvrNS = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	gvrCertPolicy = schema.GroupVersionResource{
		Group:    "policy.open-cluster-management.io",
		Version:  "v1",
		Resource: "certificatepolicies",
	}
	gvrPolicy = schema.GroupVersionResource{
		Group:    "policy.open-cluster-management.io",
		Version:  "v1",
		Resource: "policies",
	}
	gvrSecret = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}

	clientManaged = NewKubeClient("", kubeconfigManaged, "")
	clientManagedDynamic = NewKubeClientDynamic("", kubeconfigManaged, "")
	defaultImageRegistry = "quay.io/open-cluster-management"
	testNamespace = "managed"
	testNamespaces := []string{testNamespace, "range1", "range2"}
	defaultTimeoutSeconds = 90
	By("Create Namespaces if needed")
	namespaces := clientManaged.CoreV1().Namespaces()
	for _, ns := range testNamespaces {
		if _, err := namespaces.Get(context.TODO(), ns, metav1.GetOptions{}); err != nil && k8serrors.IsNotFound(err) {
			Expect(namespaces.Create(context.TODO(), &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: ns,
				},
			}, metav1.CreateOptions{})).NotTo(BeNil())
		}
		Expect(namespaces.Get(context.TODO(), ns, metav1.GetOptions{})).NotTo(BeNil())
	}
})

func NewKubeClient(url, kubeconfig, context string) kubernetes.Interface {
	klog.V(5).Infof("Create kubeclient for url %s using kubeconfig path %s\n", url, kubeconfig)

	config, err := LoadConfig(url, kubeconfig, context)
	if err != nil {
		panic(err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	return clientset
}

func NewKubeClientDynamic(url, kubeconfig, context string) dynamic.Interface {
	klog.V(5).Infof("Create kubeclient dynamic for url %s using kubeconfig path %s\n", url, kubeconfig)

	config, err := LoadConfig(url, kubeconfig, context)
	if err != nil {
		panic(err)
	}

	clientset, err := dynamic.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	return clientset
}

func LoadConfig(url, kubeconfig, context string) (*rest.Config, error) {
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

	klog.V(5).Infof("Kubeconfig path %s\n", kubeconfig)

	// If we have an explicit indication of where the kubernetes config lives, read that.
	if kubeconfig != "" {
		if context == "" {
			return clientcmd.BuildConfigFromFlags(url, kubeconfig)
		}

		return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
			&clientcmd.ConfigOverrides{
				CurrentContext: context,
			}).ClientConfig()
	}

	// If not, try the in-cluster config.
	if c, err := rest.InClusterConfig(); err == nil {
		return c, nil
	}

	// If no in-cluster config, try the default location in the user's home directory.
	if usr, err := user.Current(); err == nil {
		klog.V(5).Infof("clientcmd.BuildConfigFromFlags for url %s using %s\n", url,
			filepath.Join(usr.HomeDir, ".kube", "config"))

		if c, err := clientcmd.BuildConfigFromFlags("", filepath.Join(usr.HomeDir, ".kube", "config")); err == nil {
			return c, nil
		}
	}

	return nil, errors.New("could not create a valid kubeconfig")
}
