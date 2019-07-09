// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.

// Package admissionpolicy handles admissionpolicy controller logic
package common

import (
	"reflect"
	"testing"
	"time"

	mcmv1alpha1 "github.ibm.com/IBMPrivateCloud/PolicyFramework/pkg/apis/mcm-grcpolicy/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

/*
	apiVersion: mcm.ibm.com/v1alpha1
		kind: GRCPolicy
		metadata:
			name: GRC-policy
		spec:
			namespaces:
				include: ["default"]
				exclude: ["kube*"]
			remediationAction: enforce # or inform
			conditions:
				ownership: [ReplicaSet, Deployment, DeamonSet, ReplicationController]
*/

var duration = &metav1.Duration{Duration: time.Hour * 24 * 120}

var plc = &mcmv1alpha1.CertPolicy{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "testPolicy",
		Namespace: "default",
	},
	Spec: mcmv1alpha1.CertPolicySpec{
		RemediationAction: mcmv1alpha1.Enforce,
		NamespaceSelector: mcmv1alpha1.Target{
			Include: []string{"default"},
			Exclude: []string{"kube*"},
		},
		MinDuration: duration,
	},
}

var sm = SyncedPolicyMap{
	PolicyMap: make(map[string]*mcmv1alpha1.CertPolicy),
}

//TestGetObject testing get object in map
func TestGetObject(t *testing.T) {
	_, found := sm.GetObject("void")
	if found {
		t.Fatalf("expecting found = false, however found = %v", found)
	}

	sm.AddObject("default", plc)

	plc, found := sm.GetObject("default")
	if !found {
		t.Fatalf("expecting found = true, however found = %v", found)
	}
	if !reflect.DeepEqual(plc.Name, "testPolicy") {
		t.Fatalf("expecting plcName = testPolicy, however plcName = %v", plc.Name)
	}
}

func TestAddObject(t *testing.T) {
	sm.AddObject("default", plc)
	plcName, found := sm.GetObject("ServiceInstance")
	_, found = sm.GetObject("void")
	if found {
		t.Fatalf("expecting found = false, however found = %v", found)
	}
	if !reflect.DeepEqual(plc.Name, "testPolicy") {
		t.Fatalf("expecting plcName = testPolicy, however plcName = %v", plcName)
	}

}

func TestRemoveDataObject(t *testing.T) {
	sm.RemoveObject("void")
	_, found := sm.GetObject("void")
	if found {
		t.Fatalf("expecting found = false, however found = %v", found)
	}
	//remove after adding
	sm.AddObject("default", plc)
	sm.RemoveObject("default")
	_, found = sm.GetObject("default")
	if found {
		t.Fatalf("expecting found = false, however found = %v", found)
	}
}
