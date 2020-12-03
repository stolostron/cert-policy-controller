// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.
// Copyright (c) 2020 Red Hat, Inc.

package certificatepolicy

import (
	"fmt"
	"sort"
	"time"

	policyv1 "github.com/open-cluster-management/cert-policy-controller/pkg/apis/policies/v1"
)

var format string = "%s; %s"

//=================================================================
// convertPolicyStatusToString to be able to pass the status as event
func convertPolicyStatusToString(plc *policyv1.CertificatePolicy, defaultDuration time.Duration) (results string) {
	result := "ComplianceState is still undetermined"
	if plc.Status.ComplianceState == "" {
		return result
	}
	result = string(plc.Status.ComplianceState)

	if plc.Status.CompliancyDetails == nil {
		return fmt.Sprintf(format, result, "No namespaces matched the namespace selector.")
	}

	// Message format:
	//  NonCompliant; x certificates expire in less than 300h: namespace:secretname, namespace:secretname, ...
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

		// keep the flageed namespaces sorted
		keys := make([]string, 0, len(plc.Status.CompliancyDetails))
		for k := range plc.Status.CompliancyDetails {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, namespace := range keys {
			details := plc.Status.CompliancyDetails[namespace]
			if details.NonCompliantCertificates > 0 {
				for _, details := range details.NonCompliantCertificatesList {
					expiredCACerts, expireCACount, expiredCerts, expireCount = updateExpired(details, namespace, plc,
						expiredCACerts, expireCACount, expiredCerts, expireCount)
					durationCACerts, durationCACount, durationCerts, durationCount = updateLifetime(details, namespace,
						plc, durationCACerts, durationCACount, durationCerts, durationCount)
					patternCerts, patternMismatchCount = updateAllowed(details, namespace, plc, patternCerts,
						patternMismatchCount)
				}
			}
		}
		if expireCount > 0 {
			message = fmt.Sprintf("%d certificates expire in less than %s: %s\n",
				expireCount, minDuration.String(), expiredCerts)
		}
		if expireCACount > 0 {
			message = fmt.Sprintf("%s %d CA certificates expire in less than %s: %s\n",
				message, expireCACount, plc.Spec.MinCADuration.Duration.String(), expiredCACerts)
		}
		if durationCount > 0 {
			message = fmt.Sprintf("%s %d certificates exceed the maximum duration of %s: %s\n",
				message, durationCount, plc.Spec.MaxDuration.Duration.String(), durationCerts)
		}
		if durationCACount > 0 {
			message = fmt.Sprintf("%s %d CA certificates exceed the maximum duration of %s: %s\n",
				message, durationCACount, plc.Spec.MaxCADuration.Duration.String(), durationCACerts)
		}
		if patternMismatchCount > 0 {
			message = fmt.Sprintf("%s %d certificates defined SAN entries do not match pattern %s: %s\n",
				message, patternMismatchCount, getPatternsUsed(plc), patternCerts)
		}
		result = fmt.Sprintf(format, result, message)
	} else if plc.Status.ComplianceState == policyv1.Compliant {
		if len(plc.Status.CompliancyDetails) == 1 {
			for namespace := range plc.Status.CompliancyDetails {
				if namespace == "" {
					return fmt.Sprintf(format, result, "No namespaces matched the namespace selector.")
				}
			}
		}
	}
	return result
}

func updateExpired(details policyv1.Cert, namespace string, plc *policyv1.CertificatePolicy,
	expiredCACerts string, expireCACount int, expiredCerts string, expireCount int) (string, int, string, int) {
	certDetails := details
	if isCertificateExpiring(&certDetails, plc) {
		if certDetails.CA && plc.Spec.MinCADuration != nil {
			expiredCACerts = buildComplianceSubmessage(expiredCACerts, namespace, certDetails.Secret)
			expireCACount++
		} else {
			expiredCerts = buildComplianceSubmessage(expiredCerts, namespace, certDetails.Secret)
			expireCount++
		}
	}
	return expiredCACerts, expireCACount, expiredCerts, expireCount
}

func updateLifetime(details policyv1.Cert, namespace string, plc *policyv1.CertificatePolicy,
	durationCACerts string, durationCACount int, durationCerts string, durationCount int) (string, int, string, int) {
	certDetails := details
	if isCertificateLongDuration(&certDetails, plc) {
		if certDetails.CA && plc.Spec.MaxCADuration != nil {
			durationCACerts = buildComplianceSubmessage(durationCACerts, namespace, certDetails.Secret)
			durationCACount++
		} else {
			durationCerts = buildComplianceSubmessage(durationCerts, namespace, certDetails.Secret)
			durationCount++
		}
	}
	return durationCACerts, durationCACount, durationCerts, durationCount
}

func updateAllowed(details policyv1.Cert, namespace string, plc *policyv1.CertificatePolicy,
	patternCerts string, patternMismatchCount int) (string, int) {
	certDetails := details
	if isCertificateSANPatternMismatch(&certDetails, plc) {
		patternCerts = buildComplianceSubmessage(patternCerts, namespace, certDetails.Secret)
		patternMismatchCount++
	}
	return patternCerts, patternMismatchCount
}

func buildComplianceSubmessage(inputmsg string, namespace string, secret string) string {
	message := ""
	if len(inputmsg) > 0 {
		message = fmt.Sprintf("%s, %s:%s", inputmsg, namespace, secret)
	} else {
		message = fmt.Sprintf("%s:%s", namespace, secret)
	}
	return message
}
