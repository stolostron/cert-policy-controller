package e2e

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"open-cluster-management.io/config-policy-controller/test/utils"
)

var _ = Describe("Test certificate policy with long compliance message", Ordered, func() {
	const resources = "../resources/case2_long_messages"
	kubeconfig := "--kubeconfig=" + kubeconfigManaged

	BeforeAll(func() {
		utils.Kubectl("create", "namespace", "case2", kubeconfig)
	})

	AfterAll(func() {
		utils.Kubectl(
			"delete", "-n", testNamespace, "-f", resources+"/parent_policy.yaml", "--ignore-not-found", kubeconfig,
		)
		utils.Kubectl(
			"delete", "-n", testNamespace, "-f", resources+"/certificate_policy.yaml", "--ignore-not-found", kubeconfig,
		)
		utils.Kubectl("delete", "namespace", "case2", "--ignore-not-found", kubeconfig)
		utils.Kubectl("delete", "event", "--field-selector=involvedObject.name=case2", "-n", "managed", kubeconfig)
	})

	It("should become noncompliant even though message is beyond 1024 characters", func(ctx context.Context) {
		By("Creating the expiring certificate secrets")
		utils.Kubectl("apply", "-f", resources+"/expired_secrets.yaml", "--kubeconfig", kubeconfigManaged)

		By("Creating the Policy and CertificatePolicy")
		utils.Kubectl(
			"apply", "-f", resources+"/parent_policy.yaml", "-n", testNamespace, "--kubeconfig", kubeconfigManaged,
		)
		parentPlc := utils.GetWithTimeout(
			clientManagedDynamic, gvrPolicy, "case2", testNamespace, true, defaultTimeoutSeconds,
		)
		Expect(parentPlc).NotTo(BeNil())

		certPolicyYAML, err := os.ReadFile(resources + "/certificate_policy.yaml")
		Expect(err).ToNot(HaveOccurred())

		certPolicy := &unstructured.Unstructured{}
		err = yaml.Unmarshal(certPolicyYAML, &certPolicy.Object)
		Expect(err).ToNot(HaveOccurred())

		ownerRefs := []metav1.OwnerReference{{
			APIVersion: "policy.open-cluster-management.io/v1",
			Kind:       "Policy",
			Name:       "case2",
			UID:        parentPlc.GetUID(),
		}}
		certPolicy.SetOwnerReferences(ownerRefs)

		_, err = clientManagedDynamic.Resource(gvrCertPolicy).Namespace(testNamespace).Create(
			ctx, certPolicy, metav1.CreateOptions{},
		)
		Expect(err).ToNot(HaveOccurred())

		By("Verifying it is NonCompliant and has the long compliance message")
		Eventually(func() interface{} {
			certPlc := utils.GetWithTimeout(
				clientManagedDynamic, gvrCertPolicy, "case2", testNamespace, true, defaultTimeoutSeconds,
			)

			return utils.GetComplianceState(certPlc)
		}, defaultTimeoutSeconds, 1).Should(Equal("NonCompliant"))

		events, err := clientManaged.CoreV1().Events(testNamespace).List(
			ctx, metav1.ListOptions{FieldSelector: "involvedObject.name=case2,involvedObject.kind=Policy"},
		)
		Expect(err).ToNot(HaveOccurred())
		Expect(events.Items).ToNot(BeEmpty())

		var matched bool

		for _, event := range events.Items {
			// Client side filtering is required for this field since field selectors don't support this field.
			if event.Action != "ComplianceStateUpdate" {
				continue
			}

			Expect(len(event.Message)).To(BeNumerically(">", 1024), "Expected the event message to be greater than 1024")
			matched = true
		}

		Expect(matched).To(BeTrue(), "Expected a ComplianceStateUpdate event for the case2 Policy to be found")
	})
})
