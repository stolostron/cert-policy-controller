// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.
// Copyright (c) 2020 Red Hat, Inc.

package certificatepolicy

import (
	"encoding/json"
	"fmt"
	"time"

	policyv1 "github.com/open-cluster-management/cert-policy-controller/pkg/apis/policies/v1"
	"github.com/open-cluster-management/cert-policy-controller/pkg/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
)

//=================================================================
// convertPolicyStatusToString to be able to pass the status as event
func convertPolicyStatusToString(plc *policyv1.CertificatePolicy, defaultDuration time.Duration) (results string) {
	result := "ComplianceState is still undetermined"
	if plc.Status.ComplianceState == "" {
		return result
	}
	result = string(plc.Status.ComplianceState)

	if plc.Status.CompliancyDetails == nil {
		return fmt.Sprintf("%s; %s", result, "No namespaces matched the namespace selector.")
	}

	// Message format: NonCompliant; x certificates expire in less than 300h: namespace:secretname, namespace:secretname, namespace:secretname
	count := 0
	if plc.Status.ComplianceState == policyv1.NonCompliant {
		minDuration := defaultDuration
		if plc.Spec.MinDuration != nil {
			minDuration = plc.Spec.MinDuration.Duration
		}
		message := fmt.Sprintf("certificates expire in less than %s", minDuration.String())
		certs := ""
		for namespace, details := range plc.Status.CompliancyDetails {
			if details.NonCompliantCertificates > 0 {
				for _, certDetails := range details.NonCompliantCertificatesList {
					if len(certs) > 0 {
						certs = fmt.Sprintf("%s, %s:%s", certs, namespace, certDetails.Secret)
					} else {
						certs = fmt.Sprintf("%s:%s", namespace, certDetails.Secret)
					}
					count++
				}
			}
		}
		result = fmt.Sprintf("%s; %d %s: %s", result, count, message, certs)
	} else if plc.Status.ComplianceState == policyv1.Compliant {
		if len(plc.Status.CompliancyDetails) == 1 {
			for namespace := range plc.Status.CompliancyDetails {
				if namespace == "" {
					return fmt.Sprintf("%s; %s", result, "No namespaces matched the namespace selector.")
				}
			}
		}
	}
	return result
}

func createGenericObjectEvent(name, namespace string) {

	plc := &policyv1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "policy.open-cluster-management.io/v1",
		},
	}
	data, err := json.Marshal(plc)
	if err != nil {
		klog.Fatal(err)
	}
	found, err := common.GetGenericObject(data, namespace)
	if err != nil {
		klog.Fatal(err)
	}
	if md, ok := found.Object["metadata"]; ok {
		metadata := md.(map[string]interface{})
		if objectUID, ok := metadata["uid"]; ok {
			plc.ObjectMeta.UID = types.UID(objectUID.(string))
			reconcilingAgent.recorder.Event(plc, corev1.EventTypeWarning, "reporting --> forward", fmt.Sprintf("eventing on policy %s/%s", plc.Namespace, plc.Name))
		} else {
			klog.Errorf("the objectUID is missing from policy %s/%s", plc.Namespace, plc.Name)
			return
		}
	}

	/*
		//in case we want to use a generic recorder:
		eventBroadcaster := record.NewBroadcaster()
		eventBroadcaster.StartLogging(klog.Infof)
		eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: KubeClient.CoreV1().Events("")})
		recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "controllerAgentName"})
		recorder.Event(plc, corev1.EventTypeWarning, "some reason", fmt.Sprintf("eventing on policy %s/%s", plc.Namespace, plc.Name))
	*/
}
