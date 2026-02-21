package atom

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/handlers"
)

// Run starts a new atomdns server.
func Run(version string) {
	var (
		flagHandler bool
		flagVersion bool
		flagCheck   bool
		conffile    string
		confdata    []byte
		err         error
	)
	flag.BoolVar(&flagHandler, "H", false, "show sorted list of handlers")
	flag.BoolVar(&flagVersion, "V", false, "show version")
	flag.BoolVar(&flagCheck, "C", false, "check the configuration")

	flag.Parse()
	if flagVersion {
		fmt.Println(version)
		return
	}
	if flagHandler {
		hs := []string{}
		for h := range handlers.StringToHandler {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		fmt.Println(strings.Join(hs, "\n"))
		return
	}

	if len(flag.Args()) == 0 {
		confdata = []byte(confbuiltin)
		conffile = "<builtin>"
	} else {
		conffile = flag.Args()[0]
		confdata, err = os.ReadFile(flag.Args()[0])
		if err != nil {
			slog.Error("Failed to read configuration", slog.String("path", conffile), slog.Any("error", err))
			os.Exit(1)
		}
	}

	s, err := New(conffile, bytes.NewReader(confdata))
	if err != nil {
		slog.Error("Failed to create server", slog.Any("error", err))
		os.Exit(1)
	}
	if flagCheck {
		os.Exit(0)
	}
	s.version = version

	if err := s.Start(); err != nil {
		slog.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}

	go func() {
		// dies with process
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, syscall.SIGHUP)
		for sig := range sigchan {
			slog.Info("Received signal, reloading", "signal", sig)
			if err := s.Reload(); err != nil {
				slog.Error("Failed to reload server", slog.Any("error", err))
			}
			signal.Notify(sigchan, syscall.SIGHUP)
			if !s.global.Quiet {
				fmt.Fprintln(os.Stderr, banner(s.version))
			}
		}
	}()

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)
	if !s.global.Quiet {
		fmt.Println(banner(version))
	}
	sig := <-sigchan
	s.Shutdown(context.TODO())
	slog.Info("Received signal, stopping", "signal", sig)
}

func banner(version string) string {

	const banner = `
  ┏━┓  ╺┳╸  ┏━┓  ┏┳┓
  ┣━┫   ┃   ┃ ┃  ┃┃┃  DNS
  ╹ ╹   ╹   ┗━┛  ╹ ╹ v%s (%s)
  High performance and flexible DNS server
  https://atomdns.miek.nl
__________________________________\o/_______`
	return fmt.Sprintf(banner[1:], version, dns.Version) // [1:] remove first \n, while keeping the formatting in the const
}

const confbuiltin = `
{
	dns {
		addr [::]:1053
	}
}

example.org {
	log
	whoami
}
`

func builtinfo() []slog.Attr {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	goos, goarch, revision := "", "", ""
	if ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "GOOS":
				goos = s.Value
			case "GOARCH":
				goarch = s.Value
			case "vcs.revision":
				revision = s.Value
			}
		}
	}
	return []slog.Attr{
		slog.String("GOOS", goos),
		slog.String("GOARCH", goarch),
		slog.String("go", strings.TrimPrefix(bi.GoVersion, "go")),
		slog.String("revision", revision),
	}
}
