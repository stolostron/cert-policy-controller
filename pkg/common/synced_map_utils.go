// Licensed Materials - Property of IBM
// (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
// Note to U.S. Government Users Restricted Rights:
// Use, duplication or disclosure restricted by GSA ADP Schedule
// Contract with IBM Corp.
// Copyright Contributors to the Open Cluster Management project

package common

import (
	"sync"

	policyv1 "github.com/stolostron/cert-policy-controller/pkg/apis/policies/v1"
)

//SyncedPolicyMap a thread safe map
type SyncedPolicyMap struct {
	PolicyMap map[string]*policyv1.CertificatePolicy
	//Mx for making the map thread safe
	Mx sync.RWMutex
}

//GetObject used for fetching objects from the synced map
func (spm *SyncedPolicyMap) GetObject(key string) (value *policyv1.CertificatePolicy, found bool) {

	spm.Mx.Lock()
	defer spm.Mx.Unlock()
	//check if the map is initialized, if not initilize it
	if spm.PolicyMap == nil {
		return nil, false
	}
	if val, ok := spm.PolicyMap[key]; ok {
		return val, true
	}
	return nil, false
}

// AddObject safely add to map
func (spm *SyncedPolicyMap) AddObject(key string, plc *policyv1.CertificatePolicy) {

	spm.Mx.Lock()
	defer spm.Mx.Unlock()
	//check if the map is initialized, if not initilize it
	if spm.PolicyMap == nil {
		spm.PolicyMap = make(map[string]*policyv1.CertificatePolicy)
	}
	spm.PolicyMap[key] = plc
}

// RemoveObject safely remove from map
func (spm *SyncedPolicyMap) RemoveObject(key string) {

	spm.Mx.Lock()
	defer spm.Mx.Unlock()
	//check if the map is initialized, if not return
	if spm.PolicyMap == nil {
		return
	}
	if _, ok := spm.PolicyMap[key]; ok {
		delete(spm.PolicyMap, key)
	}
}
