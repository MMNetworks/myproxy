// package dnsctx helps with setting and getting data from the context of the current query.
// See the [Match] function source for what types are currently supported. When adding something to the
// context there is no check done on the type to not slow down the handler.
package dnsctx

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"codeberg.org/miekg/dns"
)

type Keyer interface {
	// Key returns the "key" of the handler.
	Key() string
}

// Func is a function that can be set in the context and operates on a [dns.Msg].
type Func func(*dns.Msg) *dns.Msg

type funcsKey struct{}

// WithFunc appends the Func f in the context under the funcsKey. It is not possible to retrieve a specific
// Func. You can only run through them using [Funcs].
func WithFunc(ctx context.Context, handler Keyer, f Func) context.Context {
	v := ctx.Value(funcsKey{})
	if v == nil {
		return context.WithValue(ctx, funcsKey{}, []Func{f})
	}
	return context.WithValue(ctx, funcsKey{}, append(v.([]Func), f))
}

// Predefined context keys.
const KeyStatus = "status"

// Key creates a key from the keyer and string.
func Key(handler Keyer, key string) string { return handler.Key() + "/" + key }

// Funcs iterates over all functions that are set in the context over the message. The possibly
// modified message is returned.
func Funcs(ctx context.Context, m *dns.Msg) *dns.Msg {
	v := ctx.Value(funcsKey{})
	if v == nil {
		return m
	}
	for _, f := range v.([]Func) {
		m = f(m)
	}
	return m
}

// WithValue stores value under the string value key, key must contain a slash and be formatted like
// "<handler>/xxx". If key does not contain a slash, this function is noop.
func WithValue(ctx context.Context, key string, value any) context.Context {
	if !Valid(key) {
		return ctx
	}
	return context.WithValue(ctx, key, value)
}

// Value returns the value under key. If key does not contain a slash nil is returned.
func Value(ctx context.Context, key string) any {
	if !Valid(key) {
		return ""
	}
	v := ctx.Value(key)
	if v == nil {
		return nil
	}
	return v
}

// Valid returns a boolean indicating if the key is a valid context key.
func Valid(key string) bool {
	if len(key) < 3 {
		return false
	}
	return strings.Contains(key, "/")
}

// Match checks the value under key and see if it matches any of the elements in the list.
// This function handles strings, string slices, ints, flaot64s, net.IPs and bools. A nil value for key returns true.
func Match(ctx context.Context, key string, values []any) bool {
	value := Value(ctx, key)
	if value == nil {
		return true
	}
	switch x := value.(type) {
	case bool:
		for _, v := range values {
			if b, ok := v.(bool); ok && b == x {
				return true
			}
		}
	case string:
		for _, v := range values {
			if s, ok := v.(string); ok && s == x {
				return true
			}
		}
	case []string:
		for _, v := range values {
			if slices.Contains(value.([]string), v.(string)) {
				return true
			}
		}
	case int:
		for _, v := range values {
			if i, ok := v.(int); ok && i == x {
				return true
			}
		}
	case float64:
		for _, v := range values {
			if f, ok := v.(float64); ok && f == x {
				return true
			}
		}
	case netip.Addr:
		for _, v := range values {
			if ip, ok := v.(netip.Addr); ok && ip == x {
				return true
			}
		}
	}
	return false
}
