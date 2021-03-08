// Copyright Contributors to the Open Cluster Management project

package controller

import (
	"github.com/open-cluster-management/cert-policy-controller/pkg/controller/certificatepolicy"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, certificatepolicy.Add)
}
