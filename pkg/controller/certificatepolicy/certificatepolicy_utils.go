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
	expireCount := 0
	expireCACount := 0
	durationCount := 0
	durationCACount := 0
	patternMismatchCount := 0
	if plc.Status.ComplianceState == policyv1.NonCompliant {
		minDuration := defaultDuration
		if plc.Spec.MinDuration != nil {
			minDuration = plc.Spec.MinDuration.Duration
		}
		message := ""
		expiredCerts := ""
		expiredCACerts := ""
		durationCerts := ""
		durationCACerts := ""
		patternCerts := ""
		for namespace, details := range plc.Status.CompliancyDetails {
			if details.NonCompliantCertificates > 0 {
				for _, certDetails := range details.NonCompliantCertificatesList {
					if isCertificateExpiring(&certDetails, plc) {
						if certDetails.CA && plc.Spec.MinCADuration != nil {
							if len(expiredCACerts) > 0 {
								expiredCACerts = fmt.Sprintf("%s, %s:%s", expiredCACerts, namespace, certDetails.Secret)
							} else {
								expiredCACerts = fmt.Sprintf("%s:%s", namespace, certDetails.Secret)
							}
							expireCACount++
						} else {
							if len(expiredCerts) > 0 {
								expiredCerts = fmt.Sprintf("%s, %s:%s", expiredCerts, namespace, certDetails.Secret)
							} else {
								expiredCerts = fmt.Sprintf("%s:%s", namespace, certDetails.Secret)
							}
							expireCount++
						}
					}
					if isCertificateLongDuration(&certDetails, plc) {
						if certDetails.CA && plc.Spec.MaxCADuration != nil {
							if len(durationCACerts) > 0 {
								durationCACerts = fmt.Sprintf("%s, %s:%s", durationCACerts, namespace, certDetails.Secret)
							} else {
								durationCACerts = fmt.Sprintf("%s:%s", namespace, certDetails.Secret)
							}
							durationCACount++
						} else {
							if len(durationCerts) > 0 {
								durationCerts = fmt.Sprintf("%s, %s:%s", durationCerts, namespace, certDetails.Secret)
							} else {
								durationCerts = fmt.Sprintf("%s:%s", namespace, certDetails.Secret)
							}
							durationCount++
						}
					}
					if isCertificateSANPatternMismatch(&certDetails, plc) {
						if len(patternCerts) > 0 {
							patternCerts = fmt.Sprintf("%s, %s:%s", patternCerts, namespace, certDetails.Secret)
						} else {
							patternCerts = fmt.Sprintf("%s:%s", namespace, certDetails.Secret)
						}
						patternMismatchCount++
					}
				}
			}
		}
		if expireCount > 0 {
			message = fmt.Sprintf("%d certificates expire in less than %s: %s\n", expireCount, minDuration.String(), expiredCerts)
		}
		if expireCACount > 0 {
			message = fmt.Sprintf("%s %d CA certificates expire in less than %s: %s\n", message, expireCACount, plc.Spec.MinCADuration.String(), expiredCACerts)
		}
		if durationCount > 0 {
			message = fmt.Sprintf("%s %d certificates exceed the maximum duration of %s: %s\n", message, durationCount, plc.Spec.MaxDuration.String(), durationCerts)
		}
		if durationCACount > 0 {
			message = fmt.Sprintf("%s %d CA certificates exceed the maximum duration of %s: %s\n", message, durationCACount, plc.Spec.MaxCADuration.String(), durationCACerts)
		}
		if patternMismatchCount > 0 {
			message = fmt.Sprintf("%s %d certificates defined SAN entris that do not match pattern %s: %s\n", message, patternMismatchCount, getPatternsUsed(plc), patternCerts)
		}
		result = fmt.Sprintf("%s; %s", result, message)
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
