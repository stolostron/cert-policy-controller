// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.

package grcpolicy

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang/glog"
	mcmv1alpha1 "github.ibm.com/IBMPrivateCloud/icp-cert-policy-controller/pkg/apis/mcm-grcpolicy/v1alpha1"
	"github.ibm.com/IBMPrivateCloud/icp-cert-policy-controller/pkg/common"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

//=================================================================
// convertPolicyStatusToString to be able to pass the status as event
func convertPolicyStatusToString(plc *mcmv1alpha1.CertPolicy, defaultDuration time.Duration) (results string) {
	result := "ComplianceState is still undetermined"
	if plc.Status.ComplianceState == "" {
		return result
	}
	result = string(plc.Status.ComplianceState)

	if plc.Status.CompliancyDetails == nil {
		return result
	}

	for namespace, details := range plc.Status.CompliancyDetails {
		if details.NonCompliantCertificates > 0 {
			minDuration := defaultDuration
			if plc.Spec.MinDuration != nil {
				minDuration = plc.Spec.MinDuration.Duration
			}
			result = fmt.Sprintf("%s; Non-compliant certificates (expires in less than %s) in %s[%d]:", result, minDuration.String(), namespace, details.NonCompliantCertificates)
			for cert, certDetails := range details.NonCompliantCertificatesList {
				result = fmt.Sprintf("%s [%s, %s]", result, cert, certDetails.Secret)
			}
		}
	}
	return result
}

func createGenericObjectEvent(name, namespace string) {

	plc := &mcmv1alpha1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "policy.mcm.ibm.com/v1alpha1",
		},
	}
	data, err := json.Marshal(plc)
	if err != nil {
		glog.Fatal(err)
	}
	found, err := common.GetGenericObject(data, namespace)
	if err != nil {
		glog.Fatal(err)
	}
	if md, ok := found.Object["metadata"]; ok {
		metadata := md.(map[string]interface{})
		if objectUID, ok := metadata["uid"]; ok {
			plc.ObjectMeta.UID = types.UID(objectUID.(string))
			reconcilingAgent.recorder.Event(plc, corev1.EventTypeWarning, "reporting --> forward", fmt.Sprintf("eventing on policy %s/%s", plc.Namespace, plc.Name))
		} else {
			glog.Errorf("the objectUID is missing from policy %s/%s", plc.Namespace, plc.Name)
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
