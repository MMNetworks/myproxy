//go:build windows

package httpproxy

import (
	"io"
	"net"
	"syscall"
	"errors"
)

// Library specific errors.
var (
	ErrPanic                       = NewError("panic")
	ErrResponseWrite               = NewError("response write")
	ErrRequestRead                 = NewError("request read")
	ErrRemoteConnect               = NewError("remote connect")
	ErrNotSupportHijacking         = NewError("hijacking not supported")
	ErrTLSSignHost                 = NewError("TLS sign host")
	ErrTLSHandshake                = NewError("TLS handshake")
	ErrAbsURLAfterCONNECT          = NewError("absolute URL after CONNECT")
	ErrRoundTrip                   = NewError("round trip")
	ErrUnsupportedTransferEncoding = NewError("unsupported transfer encoding")
	ErrNotSupportHTTPVer           = NewError("http version not supported")
)

// Error struct is base of library specific errors.
type Error struct {
	ErrString string
}

// NewError returns a new Error.
func NewError(errString string) *Error {
	return &Error{errString}
}

// Error implements error interface.
func (e *Error) Error() string {
	return e.ErrString
}

func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	opErr, ok := err.(*net.OpError)
	if ok {
		switch {
			case
				errors.Is(opErr, net.ErrClosed),
				errors.Is(opErr, io.EOF),
				errors.Is(opErr, syscall.ECONNRESET),
				errors.Is(opErr, syscall.EPROTOTYPE),
				errors.Is(opErr, syscall.EPIPE),
				errors.Is(opErr, syscall.WSAECONNABORTED):
				return true
			default:
				return false
		}
	}

	//if err == io.EOF {
	//	return true
	//}

	// Do not understand the below - maybe syscall error handling changed. 
	// e.g. splice: broken pipe error is not seen as EPIPE 
	// Dump shows
	// &net.OpError {
	//   ....
	//   Err: &os.SyscallError {#4
	//      Syscall: "splice",
	//      Err: 0x20,
	//   },
	// }
	// Use above instead.
	//i := 0
	//var newerr = &err
	//for opError, ok := (*newerr).(*net.OpError); ok && i < 10; {
	//	i++
	//	newerr = &opError.Err
	//	if syscallError, ok := (*newerr).(*os.SyscallError); ok {
	//		if syscallError.Err == syscall.EPIPE || syscallError.Err == syscall.ECONNRESET || syscallError.Err == syscall.EPROTOTYPE {
	//			return true
	//		}
	//	}
	//}
	return false
}
