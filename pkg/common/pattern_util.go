// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.
// Copyright Contributors to the Open Cluster Management project

package common

import (
	"strings"

	policyv1 "github.com/stolostron/cert-policy-controller/api/v1"
)

// FindPattern finds patterns.
func FindPattern(pattern string, list []string) (result []string) {
	// if pattern = "*" => all namespaces are included
	if pattern == "*" {
		return list
	}

	found := []string{}

	// if the pattern has NO "*" => do an exact search
	if !strings.Contains(pattern, "*") {
		for _, value := range list {
			if pattern == value {
				found = append(found, value)
			}
		}

		return found
	}

	// if there is a * something, we need to figure out where: it can be a leading, ending or leading and ending
	if strings.LastIndex(pattern, "*") == 0 {
		// check for has suffix of pattern - *
		substring := strings.TrimPrefix(pattern, "*")
		for _, value := range list {
			if strings.HasSuffix(value, substring) {
				found = append(found, value)
			}
		}

		return found
	}

	if strings.Index(pattern, "*") == len(pattern)-1 {
		// check for has prefix of pattern - *
		substring := strings.TrimSuffix(pattern, "*")
		for _, value := range list {
			if strings.HasPrefix(value, substring) {
				found = append(found, value)
			}
		}

		return found
	}

	if strings.LastIndex(pattern, "*") == len(pattern)-1 && strings.Index(pattern, "*") == 0 {
		substring := strings.TrimPrefix(pattern, "*")
		substring = strings.TrimSuffix(substring, "*")

		for _, value := range list {
			if strings.Contains(value, substring) {
				found = append(found, value)
			}
		}

		return found
	}

	return found
}

// DeduplicateItems does the dedup.
func DeduplicateItems(included []string, excluded []string) (res []string) {
	encountered := map[string]bool{}
	result := []string{}

	for _, inc := range included {
		encountered[inc] = true
	}

	for _, excl := range excluded {
		if encountered[excl] {
			delete(encountered, excl)
		}
	}

	for key := range encountered {
		result = append(result, key)
	}

	return result
}

// ExtractNamespaceLabel to find out the cluster-namespace from the label.
func ExtractNamespaceLabel(instance *policyv1.CertificatePolicy) string {
	if instance.ObjectMeta.Labels == nil {
		return ""
	}

	if _, ok := instance.ObjectMeta.Labels["policy.open-cluster-management.io/cluster-namespace"]; ok {
		return instance.ObjectMeta.Labels["policy.open-cluster-management.io/cluster-namespace"]
	}

	return ""
}
