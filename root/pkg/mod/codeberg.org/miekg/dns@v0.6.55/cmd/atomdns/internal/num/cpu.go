package num

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// CPU parses the string s to see if it contains NumCPU()* (with the star), if so the number behind
// it (without a space) multiplied with runtime.CPU() and returns, otherwise a number if assumed and that
// is parsed. A negative number returns an error if seen after `numcpu()*`, but we allow -1 in the normal
// expression.
func CPU(s string) (int, error) {
	const numcpu = "numcpu()*"
	if strings.HasPrefix(strings.ToLower(s), numcpu) {
		n, err := strconv.Atoi(s[len(numcpu):])
		if err != nil || n < 0 {
			return 0, fmt.Errorf("not a (positive) number after %s: %q", numcpu, s)
		}
		return runtime.NumCPU() * n, nil
	}

	n, err := strconv.Atoi(s)
	if err != nil || n < -1 {
		return 0, fmt.Errorf("not a number or less than -1: %q", s)
	}
	return n, nil

}
