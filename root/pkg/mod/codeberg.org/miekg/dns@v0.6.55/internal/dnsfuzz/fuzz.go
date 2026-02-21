package dnsfuzz

import (
	"os"
	"testing"
	"time"
)

// Stop returns true when the fuzz test should stop. If gets the duration from the environment variable FUZZ
// which should contain a Go duration string like '20m', or '10h'. If FUZZ is empty or can't be found true is
// returned.
func Stop(t *testing.T, start time.Time) bool {
	fuzz := os.Getenv("FUZZ")
	if fuzz == "" {
		return true
	}
	d, err := time.ParseDuration(fuzz)
	if err != nil {
		return false
	}
	ok := time.Since(start) > d
	if ok {
		t.Logf("Stopping fuzzing after: %s", d)
		t.FailNow()
	}
	return ok
}
