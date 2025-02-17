package e2e

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"open-cluster-management.io/config-policy-controller/test/utils"
)

var _ = Describe("Test cert policy metrics", Ordered, func() {
	const (
		policyName       = "case3-policy"
		policyYaml       = "../resources/case3_metrics/certificate_policy.yaml"
		certNamespace    = "case3"
		nonCompliantCert = "../resources/case3_metrics/expired_secret.yaml"
		compliantCert    = "../resources/case3_metrics/unexpired_secret.yaml"
	)

	metricCheck := func(metricName string, label string, value string) (float64, error) {
		metric, err := getMetrics(
			metricName, fmt.Sprintf(`%s=\"%s\"`, label, value))
		if err != nil {
			return 0, err
		}
		if len(metric) == 0 {
			return 0, fmt.Errorf("failed to retrieve any %s metric", metricName)
		}
		metricVal, err := strconv.ParseFloat(metric[0], 64)
		if err != nil {
			return 0, fmt.Errorf("error converting metric: %w", err)
		}

		return metricVal, nil
	}

	BeforeAll(func() {
		By("Creating " + policyYaml)
		utils.Kubectl("apply", "-f", policyYaml, "-n", testNamespace)
		By("Creating 'case3' namespace")
		utils.Kubectl("create", "namespace", certNamespace)
		By("Creating " + nonCompliantCert)
		utils.Kubectl("apply", "-f", nonCompliantCert, "-n", certNamespace)
	})

	It("should correctly report reconcile duration for the controller", func() {
		By("Checking metric endpoint for reconcile duration")
		Eventually(
			metricCheck, defaultTimeoutSeconds, 1,
		).WithArguments("cert_policy_reconcile_seconds", "le", "+Inf").Should(BeNumerically(">", 0))
	})

	It("should correctly report total evaluations for the certificatepolicy", func() {
		By("Checking metric endpoint for total evaluations")
		Eventually(
			metricCheck, defaultTimeoutSeconds, 1,
		).WithArguments("cert_policy_evaluation_total", "name", policyName).Should(BeNumerically(">", 0))
	})

	It("should report total evaluation duration for the certificatepolicy", func() {
		By("Checking metric endpoint for total evaluation duration")
		Eventually(
			metricCheck, defaultTimeoutSeconds, 1,
		).WithArguments("cert_policy_evaluation_seconds_total", "name", policyName).Should(BeNumerically(">", 0))
	})

	It("should report status for the certificatepolicy", func() {
		By("Checking metric endpoint for configuration policy status")
		Eventually(
			metricCheck, defaultTimeoutSeconds, 1,
		).WithArguments("cluster_policy_governance_info", "policy", policyName).Should(BeNumerically("==", 1))

		By("Updating the certificate to make the policy compliant")
		utils.Kubectl("apply", "-f", compliantCert, "-n", certNamespace)
		Eventually(
			metricCheck, defaultTimeoutSeconds, 1,
		).WithArguments("cluster_policy_governance_info", "policy", policyName).Should(BeNumerically("==", 0))
	})

	AfterAll(func() {
		utils.KubectlDelete("-n", testNamespace, "-f", policyYaml)
		utils.KubectlDelete("namespace", certNamespace)

		for metricName, label := range map[string]string{
			"cert_policy_evaluation_total":         "name",
			"cert_policy_evaluation_seconds_total": "name",
			"cluster_policy_governance_info":       "policy",
		} {
			Eventually(
				getMetrics, defaultTimeoutSeconds, 1,
			).WithArguments(metricName, fmt.Sprintf(`%s=\"%s\"`, label, policyName)).Should(HaveLen(0))
		}
	})
})

// getMetrics execs into the cert-policy-controller pod and curls the metrics
// endpoint, filters the response with the given patterns, and returns the
// value(s) for the matching metric(s).
func getMetrics(metricPatterns ...string) ([]string, error) {
	podCmd := exec.Command("kubectl", "get", "pod", "-n=open-cluster-management-agent-addon",
		"-l=name=cert-policy-controller", "--no-headers", "--kubeconfig=../../kubeconfig_managed_e2e")

	propPodInfo, err := podCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Error running '%s'\n: %s: %w", strings.Join(podCmd.Args, " "), propPodInfo, err)
	}

	var cmd *exec.Cmd

	metricFilter := " | grep " + strings.Join(metricPatterns, " | grep ")
	metricsCmd := `curl localhost:8383/metrics` + metricFilter

	// The pod name is "No" when the response is "No resources found"
	propPodName := strings.Split(string(propPodInfo), " ")[0]
	if propPodName == "No" || propPodName == "" {
		// A missing pod could mean the controller is running locally
		cmd = exec.Command("bash", "-c", metricsCmd)
	} else {
		cmd = exec.Command("kubectl", "exec", "-n=open-cluster-management-agent-addon", propPodName, "-c",
			"cert-policy-controller", "--kubeconfig=../../kubeconfig_managed_e2e", "--", "bash", "-c", metricsCmd)
	}

	matchingMetricsRaw, err := cmd.Output()
	if err != nil {
		if err.Error() == "exit status 1" {
			return []string{}, nil // exit 1 indicates that grep couldn't find a match.
		}

		return nil, fmt.Errorf("Error running '%s'\n: %s: %w", strings.Join(cmd.Args, " "), matchingMetricsRaw, err)
	}

	matchingMetrics := strings.Split(strings.TrimSpace(string(matchingMetricsRaw)), "\n")
	values := make([]string, len(matchingMetrics))

	for i, metric := range matchingMetrics {
		fields := strings.Fields(metric)
		if len(fields) > 0 {
			values[i] = fields[len(fields)-1]
		}
	}

	return values, nil
}
