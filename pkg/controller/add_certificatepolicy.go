package controller

import (
	"github.com/stolostron/cert-policy-controller/pkg/controller/certificatepolicy"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, certificatepolicy.Add)
}
