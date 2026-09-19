package detector_test

import (
	"testing"

	"github.com/m-mizutani/gt"
)

// wantFired asserts the fired flag against the expectation.
func wantFired(t *testing.T, fired, want bool) {
	t.Helper()
	if want {
		gt.Bool(t, fired).True()
	} else {
		gt.Bool(t, fired).False()
	}
}
