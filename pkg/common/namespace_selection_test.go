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

package common

import (
	"context"
	"log"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	testclient "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	policiesv1 "github.com/open-cluster-management/cert-policy-controller/api/v1"
)

var c client.Client

var depKey = types.NamespacedName{Name: "default"}

const timeout = time.Second * 5

func TestCreateNamespace(t *testing.T) {
	t.Parallel()

	g := gomega.NewGomegaWithT(t)

	// Setup the Manager and Controller.  Wrap the Controller Reconcile function so it writes each request to a
	// channel when it is finished.
	mgr, _ := manager.New(cfg, manager.Options{})
	c = mgr.GetClient()

	stopFunc, mgrStopped := StartTestManager(mgr, g)

	defer func() {
		stopFunc()
		mgrStopped.Wait()
	}()

	// making sure the namespace created is accessible
	name := "my-name"
	instance := createNamespace(name)
	depKey = types.NamespacedName{Name: name}

	err := c.Create(context.TODO(), instance)
	if apierrors.IsInvalid(err) {
		t.Logf("failed to create object, got an invalid object error: %v", err)

		return
	}

	g.Eventually(func() error { return c.Get(context.TODO(), depKey, instance) }, timeout).
		Should(gomega.Succeed())
}

func TestGetSelectedNamespaces(t *testing.T) {
	t.Parallel()
	// testing the actual logic
	allNamespaces := []string{"default", "dev-accounting", "dev-HR", "dev-research", "kube-public", "kube-sys"}
	included := []policiesv1.NonEmptyString{"dev-*", "kube-*", "default"}
	excluded := []policiesv1.NonEmptyString{"dev-research", "kube-sys"}
	expectedResult := []string{"default", "dev-accounting", "dev-HR", "kube-public"}
	actualResult := GetSelectedNamespaces(included, excluded, allNamespaces)

	if len(expectedResult) != len(actualResult) {
		t.Errorf("expectedResult = %v, however actualResult = %v", expectedResult, actualResult)

		return
	}

	sort.Strings((expectedResult))
	sort.Strings((actualResult))

	if !reflect.DeepEqual(actualResult, expectedResult) {
		t.Errorf("expectedResult = %v, however actualResult = %v", expectedResult, actualResult)

		return
	}
}

func createNamespace(nsName string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
		},
	}
}

func TestGetAllNamespaces(t *testing.T) {
	t.Parallel()

	typeMeta := metav1.TypeMeta{
		Kind: "namespace",
	}
	objMeta := metav1.ObjectMeta{
		Name: "default",
	}
	ns := corev1.Namespace{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
	}

	var simpleClient kubernetes.Interface = testclient.NewSimpleClientset()
	if _, err := simpleClient.CoreV1().Namespaces().Create(context.TODO(), &ns, metav1.CreateOptions{}); err != nil {
		log.Fatal(err)
	}

	Initialize(&simpleClient, nil)

	_, err := GetAllNamespaces()
	assert.Nil(t, err)
}
