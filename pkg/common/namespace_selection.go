// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.
// Copyright Contributors to the Open Cluster Management project

package common

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyv1 "open-cluster-management.io/cert-policy-controller/api/v1"
)

//=================================================================
// GetSelectedNamespaces returns the list of filtered namespaces according to the policy namespace selector.
func GetSelectedNamespaces(included []policyv1.NonEmptyString, excluded []policyv1.NonEmptyString,
	allNamespaces []string,
) []string {
	// get all namespaces
	// allNamespaces := getAllNamespaces() //TODO change this to call the func
	// then get the list of included
	includedNamespaces := []string{}

	for _, value := range included {
		found := FindPattern(string(value), allNamespaces)
		if found != nil {
			includedNamespaces = append(includedNamespaces, found...)
		}
	}
	// then get the list of excluded
	excludedNamespaces := []string{}

	for _, value := range excluded {
		found := FindPattern(string(value), allNamespaces)
		if found != nil {
			excludedNamespaces = append(excludedNamespaces, found...)
		}
	}

	// then get the list of deduplicated
	finalList := DeduplicateItems(includedNamespaces, excludedNamespaces)

	return finalList
}

//=================================================================
//GetAllNamespaces gets the list of all namespaces from k8s.
func GetAllNamespaces() (list []string, err error) {
	namespaces := (*KubeClient).CoreV1().Namespaces()
	namespaceList, err := namespaces.List(context.TODO(), metav1.ListOptions{})

	namespacesNames := []string{}
	for _, n := range namespaceList.Items {
		namespacesNames = append(namespacesNames, n.Name)
	}

	return namespacesNames, err
}
