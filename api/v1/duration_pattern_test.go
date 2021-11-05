// Copyright Contributors to the Open Cluster Management project

package v1_test

import (
	"fmt"
	"regexp"
	"testing"
)

// Tests that the pattern in deploy/crds/kustomize/patches.json is valid.
// When updating that file, also update these tests.
const durationPattern = "^(?:(?:[0-9]+(?:.[0-9])?)(?:h|m|s|(?:ms)|(?:us)|(?:ns)))+$"

func TestPattern(t *testing.T) {
	t.Parallel()
	regex := regexp.MustCompile(durationPattern)

	tests := []struct {
		duration string
		expected bool
	}{
		{"1h", true},
		{"1.5h", true},
		{"1.h", false},
		{"2h45m30s", true},
		{"-2h45m", false},
		{"1m3ms", true},
		{"1us", true},
		{"2ns", true},
		{"1.5.3h", false},
	}

	for _, test := range tests {
		test := test
		t.Run(
			fmt.Sprintf("duration=%s,expected=%v", test.duration, test.expected),
			func(t *testing.T) {
				result := regex.Match([]byte(test.duration))
				if test.expected != result {
					t.Fatalf("expected %v, got %v", test.expected, result)
				}
			},
		)
	}
}
