package log

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsctx"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

var (
	state     atomic.Bool
	startonce sync.Once
	shutonce  sync.Once
)

func valid(val string) error {
	if !dnsctx.Valid(val) {
		return fmt.Errorf("invalid context key: %s", val)
	}
	if slices.Contains([]string{"ecs/addr", "id/id"}, val) {
		return fmt.Errorf("default context key used: %s", val)
	}
	return nil
}

func split(val string) (handler, key string) {
	before, after, _ := strings.Cut(val, "/")
	return before, after
}

func (l *Log) Setup(co *dnsserver.Controller) error {
	l.Contexts = map[string][]string{}
	l.UnixAddr = co.Global.UnixAddr

	co.Next() // "log"
	if co.NextBlock(0) {
		err := valid(co.Val())
		if err != nil {
			return co.PropErr(err)
		}
		h, k := split(co.Val())
		l.Contexts[h] = append(l.Contexts[h], k)

		for co.NextLine() {
			if co.Val() == "}" {
				break
			}
			err := valid(co.Val())
			if err != nil {
				return co.PropErr(err)
			}
			h, k := split(co.Val())
			l.Contexts[h] = append(l.Contexts[h], k)
		}
	}

	state.Store(!co.Global.Disable)
	ctx, cancel := context.WithCancel(context.Background())

	co.OnStartup(func() error {
		startonce.Do(func() {
			_log().Info("Startup", "signal", "USR1", slog.Bool("enabled", !co.Global.Disable))
			sigchan := make(chan os.Signal, 1)
			go func() {
				signal.Notify(sigchan, SIGUSR1)
				for {
					select {
					case <-sigchan:
						signal.Notify(sigchan, SIGUSR1)
						if state.Load() {
							_log().Info("Received signal, disabling query logging")
							state.Store(false)
						} else {
							_log().Info("Received signal, enabling query logging")
							state.Store(true)
						}
					case <-ctx.Done():
						return
					}
				}
			}()
		})
		return nil
	})

	co.OnShutdown(func() error {
		shutonce.Do(func() {
			_log().Info("Shutdown", "signal", "USR1")
			cancel()
		})
		return nil
	})

	co.OnReset(func() {
		startonce = sync.Once{}
		shutonce = sync.Once{}
	})

	return nil
}
