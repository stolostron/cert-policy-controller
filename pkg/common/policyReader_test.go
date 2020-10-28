// Copyright (c) 2020 Red Hat, Inc.

package common

import (
	"encoding/json"
	"testing"

	policyv1 "github.com/open-cluster-management/cert-policy-controller/pkg/apis/policies/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetGenericObject(t *testing.T) {

	plc := &policyv1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "policy.open-cluster-management.io/v1",
		},
	}

	data, err := json.Marshal(plc)
	assert.Nil(t, err)

	found, err := GetGenericObject(data, "default")
	assert.NotNil(t, err)
	assert.NotNil(t, found)
}
