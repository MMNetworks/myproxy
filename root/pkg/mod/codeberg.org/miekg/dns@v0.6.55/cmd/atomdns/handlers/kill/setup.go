package kill

import (
	"log/slog"
	"os"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (k *Kill) Setup(co *dnsserver.Controller) error {
	for co.Next() {
		args, err := co.RemainingDurations()
		if err != nil {
			return co.PropErr(err)
		}
		if len(args) != 1 {
			return co.ArgErr()
		}
		co.OnStartup(func() error {
			log().Info("Startup", slog.Duration("after", args[0]))
			return nil
		})
		go func() {
			boom := time.NewTimer(args[0])
			<-boom.C
			log().Info("Shutdown", slog.Duration("after", args[0]))
			os.Exit(0)
		}()
	}
	return nil
}
