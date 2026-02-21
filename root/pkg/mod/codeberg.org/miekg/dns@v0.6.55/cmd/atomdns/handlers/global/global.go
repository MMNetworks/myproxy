package global

import (
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
)

type Global struct {
	// Root
	Root string
	// Logging
	Debug   bool
	Quiet   bool
	Disable bool
	// Metrics
	MetricsN        uint64
	MetricsListener net.Listener
	// Health
	Lameduck       time.Duration
	HealthListener net.Listener
	// Pprof
	PprofListener net.Listener
	// dns
	Addr   string
	Limits Limits
	// doh
	HttpAddr   string
	HttpLimits Limits
	// dot
	TlsAddr   string
	TlsLimits Limits
	// dou
	UnixAddr   string
	UnixLimits Limits
	// tls
	TlsConfig     *tls.Config // manual
	TlsCertConfig *certmagic.Config
	TlsIPs        []string // lets-encrypt, IP to get certs for
	TlsContact    string   // lets-encrypt
	TlsPath       string   // lets-encrypt

	onceStartup  sync.Once
	onceShutdown sync.Once
	onceReset    sync.Once
	onStartup    []func() error // Functions to execute on startup
	onShutdown   []func() error // Function to execute on shutdown
	onReset      []func()       // Function to execute after shutdown has been called

	Config     string              // path to config file
	Registered map[string]struct{} // registered zones
}

func (g *Global) OnStartup(fn func() error)  { g.onStartup = append(g.onStartup, fn) }
func (g *Global) OnShutdown(fn func() error) { g.onShutdown = append(g.onShutdown, fn) }
func (g *Global) OnReset(fn func())          { g.onReset = append(g.onReset, fn) }

func (g *Global) Startup() error {
	errs := []error{}
	wg := sync.WaitGroup{}
	g.onceStartup.Do(func() {
		if len(g.onStartup) > 0 {
			slog.Info("Startup functions", slog.Int("total", len(g.onStartup)))
		}
		wg.Go(func() {
			for _, fn := range g.onStartup {
				if err := fn(); err != nil {
					errs = append(errs, err)
				}
			}
		})
	})
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}

	return nil
}

func (g *Global) Shutdown() error {
	errs := []error{}
	wg := sync.WaitGroup{}
	g.onceShutdown.Do(func() {
		if len(g.onShutdown) > 0 {
			slog.Info("Shutdown functions", slog.Int("total", len(g.onShutdown)))
		}
		for _, fn := range g.onShutdown {
			wg.Go(func() {
				if err := fn(); err != nil {
					errs = append(errs, err)
				}
			})
		}
	})
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	g.onceReset.Do(func() {
		for _, fn := range g.onReset {
			fn()
		}
	})
	g.onceReset = sync.Once{}
	return nil
}
