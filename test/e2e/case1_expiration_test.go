// Copyright (c) 2020 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package e2e

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"open-cluster-management.io/cert-policy-controller/controllers"
	"open-cluster-management.io/cert-policy-controller/test/utils"
)

const (
	case1CertPolicyName       string = "policy-cert-expiration"
	case1SecretName           string = "expired-cert"
	case1ExpiredCertificate   string = "../resources/case1_certificate/case1_expired_secret.yaml"
	case1UnexpiredCertificate string = "../resources/case1_certificate/case1_unexpired_secret.yaml"
	case1ParentPolicyYaml     string = "../resources/case1_certificate/case1_parent_policy.yaml"
	case1PolicyYaml           string = "../resources/case1_certificate/case1_certificate_policy.yaml"
	envName                   string = "TARGET_KUBECONFIG_PATH"
)

var _ = Describe("Test hosted certificate policy expiration", Ordered, Label("hosted-mode"), func() {
	var targetK8sClient *kubernetes.Clientset
	var altKubeconfigPath string

	BeforeAll(func() {
		By("Checking that the " + envName + " environment variable is valid")
		altKubeconfigPath = os.Getenv(envName)
		Expect(altKubeconfigPath).ToNot(Equal(""))

		targetK8sConfig, err := clientcmd.BuildConfigFromFlags("", altKubeconfigPath)
		Expect(err).ToNot(HaveOccurred())

		targetK8sClient, err = kubernetes.NewForConfig(targetK8sConfig)
		Expect(err).ToNot(HaveOccurred())
	})

	AfterAll(func() {
		utils.Kubectl("delete", "-f", case1PolicyYaml, "-n", testNamespace)

		err := targetK8sClient.CoreV1().Secrets("default").Delete(context.TODO(), case1SecretName, metav1.DeleteOptions{})
		if !errors.IsNotFound(err) {
			Expect(err).ToNot(HaveOccurred())
		}
	})

	It("should be created properly on the managed cluster", func() {
		By("Creating " + case1PolicyYaml + " on managed")
		utils.Kubectl("apply", "-f", case1PolicyYaml, "-n", testNamespace)
		plc := utils.GetWithTimeout(clientManagedDynamic, gvrCertPolicy,
			case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)
		Expect(plc).NotTo(BeNil())
		Eventually(func() interface{} {
			managedPlc := utils.GetWithTimeout(clientManagedDynamic, gvrCertPolicy,
				case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)

			return utils.GetComplianceState(managedPlc)
		}, defaultTimeoutSeconds, 1).Should(Equal("Compliant"))
	})
	It("should create expired certificate on managed cluster", func() {
		By("creating " + case1ExpiredCertificate + " on managed cluster")
		utils.Kubectl("apply", "-f", case1ExpiredCertificate, "--kubeconfig="+altKubeconfigPath)
		Eventually(func() interface{} {
			managedPlc := utils.GetWithTimeout(clientManagedDynamic, gvrCertPolicy,
				case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)

			return utils.GetComplianceState(managedPlc)
		}, defaultTimeoutSeconds, 1).Should(Equal("NonCompliant"))
	})
	It("should become Compliant with unexpired certificate on managed cluster", func() {
		utils.Kubectl("apply", "-f", case1UnexpiredCertificate, "--kubeconfig="+altKubeconfigPath)
		Eventually(func() interface{} {
			managedPlc := utils.GetWithTimeout(clientManagedDynamic, gvrCertPolicy,
				case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)

			return utils.GetComplianceState(managedPlc)
		}, defaultTimeoutSeconds, 1).Should(Equal("Compliant"))
	})
})

var _ = Describe("Test certificate policy expiration", Ordered, func() {
	AfterAll(func() {
		utils.Kubectl("delete", "-f", case1ParentPolicyYaml, "-n", testNamespace, "--ignore-not-found")
		utils.Kubectl("delete", "-f", case1PolicyYaml, "-n", testNamespace, "--ignore-not-found")
		utils.Kubectl("delete", "secret", case1SecretName, "-n", "default", "--ignore-not-found")
		utils.Kubectl("delete", "events", "-n", testNamespace, "--all")
	})

	It("should be created properly on the managed cluster", func(ctx context.Context) {
		By("Creating " + case1ParentPolicyYaml + " on managed")
		utils.Kubectl("apply", "-f", case1ParentPolicyYaml, "-n", testNamespace)
		parentPlc := utils.GetWithTimeout(clientManagedDynamic, gvrPolicy,
			case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)
		Expect(parentPlc).NotTo(BeNil())

		By("Creating " + case1PolicyYaml + " on managed")
		certPolicyYAML, err := os.ReadFile(case1PolicyYaml)
		Expect(err).ToNot(HaveOccurred())

		certPolicy := &unstructured.Unstructured{}
		err = yaml.Unmarshal(certPolicyYAML, &certPolicy.Object)
		Expect(err).ToNot(HaveOccurred())

		ownerRefs := []metav1.OwnerReference{{
			APIVersion: "policy.open-cluster-management.io/v1",
			Kind:       "Policy",
			Name:       case1CertPolicyName,
			UID:        parentPlc.GetUID(),
		}}
		certPolicy.SetOwnerReferences(ownerRefs)

		_, err = clientManagedDynamic.Resource(gvrCertPolicy).Namespace(testNamespace).Create(
			ctx, certPolicy, metav1.CreateOptions{},
		)
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() interface{} {
			managedPlc := utils.GetWithTimeout(clientManagedDynamic, gvrCertPolicy,
				case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)

			return utils.GetComplianceState(managedPlc)
		}, defaultTimeoutSeconds, 1).Should(Equal("Compliant"))
	})
	It("should create expired certificate on managed cluster", func() {
		By("creating " + case1ExpiredCertificate + " on managed cluster")
		utils.Kubectl("apply", "-f", case1ExpiredCertificate)
		Eventually(func() interface{} {
			managedPlc := utils.GetWithTimeout(clientManagedDynamic, gvrCertPolicy,
				case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)

			return utils.GetComplianceState(managedPlc)
		}, defaultTimeoutSeconds, 1).Should(Equal("NonCompliant"))
	})
	It("should become Compliant with unexpired certificate on managed cluster", func() {
		utils.Kubectl("apply", "-f", case1UnexpiredCertificate)
		Eventually(func() interface{} {
			managedPlc := utils.GetWithTimeout(clientManagedDynamic, gvrCertPolicy,
				case1CertPolicyName, testNamespace, true, defaultTimeoutSeconds)

			return utils.GetComplianceState(managedPlc)
		}, defaultTimeoutSeconds, 1).Should(Equal("Compliant"))
	})

	It("should have the database IDs on the events", func(ctx context.Context) {
		eventList, err := clientManaged.CoreV1().Events(testNamespace).List(
			ctx, metav1.ListOptions{FieldSelector: "involvedObject.name=policy-cert-expiration"},
		)
		Expect(err).ToNot(HaveOccurred())

		Expect(eventList.Items).ToNot(BeEmpty())

		for _, event := range eventList.Items {
			if event.Action != "ComplianceStateUpdate" {
				continue
			}

			Expect(event.Annotations[controllers.ParentDBIDAnnotation]).To(Equal("3"))
			Expect(event.Annotations[controllers.PolicyDBIDAnnotation]).To(Equal("5"))
		}
	})
})
