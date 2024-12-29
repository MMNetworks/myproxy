//go:build !windows

package service

func Service(args []string) {

	runProxy(args[:])

	return
}
