// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.

package grcpolicy

import (
	"testing"
	"time"

	"github.com/onsi/gomega"
	mcmv1alpha1 "github.ibm.com/IBMPrivateCloud/PolicyFramework/pkg/apis/mcm-grcpolicy/v1alpha1"
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

const timeout = time.Second * 5

func TestReconcile(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	instance := &mcmv1alpha1.CertPolicy{ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "default"}}

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

	g.Eventually(func() error { return c.Get(context.TODO(), depKey, instance) }, timeout).
		Should(gomega.Succeed())

	//g.Expect(c.Delete(context.TODO(), instance)).NotTo(gomega.HaveOccurred())
	//g.Eventually(requests, timeout).Should(gomega.Receive(gomega.Equal(expectedRequest)))

	t.Logf("failed to create object, got an invalid object error: %v", requests)

	// Note, this does not work because of the finalizer I added
	// Manually delete policy since GC isn't enabled in the test control plane
	//g.Expect(c.Delete(context.TODO(), policy)).To(gomega.Succeed())

}

func createPolicy(policyName, PolicyNamespace string, remediation mcmv1alpha1.RemediationAction) (plc *mcmv1alpha1.CertPolicy) {
	duration := &metav1.Duration{Duration: time.Hour * 24 * 120}
	return &mcmv1alpha1.CertPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName,
			Namespace: PolicyNamespace,
		},
		Spec: mcmv1alpha1.CertPolicySpec{
			RemediationAction: remediation,
			NamespaceSelector: mcmv1alpha1.Target{
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
