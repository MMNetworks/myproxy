package dnsserver

import (
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/handlers/global"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
)

//go:generate go run string_generate.go

// Controller is used by handlers to parse their config.
type Controller struct {
	conffile.Dispenser
	Global *global.Global
}

// OnStartup and OnShutdown can be used by handlers to register startup and shutdown functions. Each function
// is execute once during starting and shutting of the server. OnReset is called after OnShutdown to clear
// anything out that can prevent a clean reload, think [sync.Once] mutexes.
func (c *Controller) OnStartup(fn func() error)  { c.Global.OnStartup(fn) }
func (c *Controller) OnShutdown(fn func() error) { c.Global.OnShutdown(fn) }
func (c *Controller) OnReset(fn func())          { c.Global.OnReset(fn) }

// NewTestController create a controller useful for tests.
func NewTestController(input string) *Controller {
	d := conffile.NewTestDispenser(input)
	return &Controller{Dispenser: d, Global: &global.Global{}}
}

func (c *Controller) Path() string {
	p := c.Val()
	p = conffile.Tilde(p)
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Global.Root, p)
}

func (c *Controller) RemainingPaths() []string {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return nil
	}

	paths := make([]string, len(args))
	for i, arg := range args {
		paths[i] = conffile.Tilde(arg)

		if filepath.IsAbs(paths[i]) {
			continue
		}
		paths[i] = filepath.Join(c.Global.Root, paths[i])
	}
	return paths
}
