package handlers

import (
	"context"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

//go:generate go run string_generate.go
//go:generate go run err_generate.go

// A Handler is a dns.HandlerFunc that has a handler func (the next when to call in the middleware stack) as
// input and returns a handle func which is the handler itself.
//
// There are several types of handlers that you can implement, handlers that:
//
//   - observe, things like logging and metrics.
//   - modify the [dns.Msg] and then call the next handler, they can enrich the context or modify the message.
//   - call the next handler, wait for it to return and modify the [dns.Msg], think of setting TSIG or a DNS
//     cookie.
//
// If a Handler implements HandleFunc that returns a nil, instead of a proper dns.HandlerFunc, it is
// considered a noop handler and not added to the handlers chain. For the Handler to be useful it should
// implement [Setupper], because without it would be a comletely useless handler.
type Handler interface {
	// HandlerFunc run the handler's code.
	HandlerFunc(next dns.HandlerFunc) dns.HandlerFunc

	// Err returns a error with some extra data that identifies the handler in erroring. This method can be
	// created with go generate, once some scaffolding is in place.
	Err(error) error
}

// Setupper holds a single method that is called when this Handler has configuration that needs to be parsed
// from the config file. The co's Global holds the server's global config.
type Setupper interface {
	Setup(co *dnsserver.Controller) error
}

// Compile takes the Handlers hs and creates a wrapped handle func.
func Compile(hs []Handler) dns.HandlerFunc {
	if len(hs) < 1 {
		panic("atomdns: need something compile")
	}

	wrapped := func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {}
	for i := len(hs) - 1; i >= 0; i-- { // loop in reverse to preserve middleware order
		wrapped = hs[i].HandlerFunc(wrapped)
	}
	return wrapped
}
