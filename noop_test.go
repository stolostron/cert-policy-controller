// Copyright (c) 2026 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package main

import "testing"

// This test prevents a `go: no such tool "covdata"` error, and other errors that
// can occur in the test report if no tests are executed here.

func TestNoop(_ *testing.T) {
}
