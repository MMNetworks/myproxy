package global

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/zlog"
	"codeberg.org/miekg/dns/dnshttp"
	"github.com/caddyserver/certmagic"
)

func (g *Global) SetupTLS(d *conffile.Dispenser) error {
	certmagic.DefaultACME.Profile = "shortlived" // https://letsencrypt.org/2025/01/16/6-day-and-ip-certs
	certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	certmagic.DefaultACME.Logger = zlog.New(g.Debug)

	for d.NextBlock(0) {
		switch d.Val() {
		case "cert":
			args := d.RemainingArgs() // we don't have co.RemainingPaths there
			if len(args) != 2 {
				return d.ArgErr()
			}
			if !filepath.IsAbs(args[0]) {
				args[0] = filepath.Join(g.Root, args[0])
			}
			if !filepath.IsAbs(args[1]) {
				args[1] = filepath.Join(g.Root, args[1])
			}
			cert, err := tls.LoadX509KeyPair(args[0], args[1])
			if err != nil {
				return fmt.Errorf("could not load TLS certificate pair: %s", err)
			}
			if g.TlsConfig != nil {
				g.TlsConfig.Certificates = []tls.Certificate{cert}
				g.TlsConfig.NextProtos = dnshttp.NextProtos
			} else {
				g.TlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
					NextProtos:   dnshttp.NextProtos,
					MinVersion:   tls.VersionTLS12,
				}
			}
		case "rootca":
			var roots *x509.CertPool
			args := d.RemainingArgs() // we don't have co.RemainingPaths in d
			if len(args) != 1 {
				return d.ArgErr()
			}
			if !filepath.IsAbs(args[0]) {
				args[0] = filepath.Join(g.Root, args[0])
			}
			roots, err := loadCA(args[0])
			if err != nil {
				return d.PropErr(err)
			}
			certmagic.DefaultACME.TrustedRoots = roots
			if g.TlsConfig != nil {
				g.TlsConfig.NextProtos = dnshttp.NextProtos
				g.TlsConfig.RootCAs = roots
			} else {
				g.TlsConfig = &tls.Config{
					NextProtos: dnshttp.NextProtos,
					RootCAs:    roots,
					MinVersion: tls.VersionTLS12,
				}
			}
		case "contact":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			if _, err := mail.ParseAddress(args[0]); err != nil {
				return d.PropErr(err)
			}
			g.TlsContact = args[0]
			certmagic.DefaultACME.Email = g.TlsContact
			certmagic.DefaultACME.Agreed = true
		case "path":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			if !filepath.IsAbs(args[0]) {
				args[0] = filepath.Join(g.Root, args[0])
			}
			g.TlsPath = args[0]
			certmagic.Default.Storage = &certmagic.FileStorage{Path: g.TlsPath}
		case "source":
			args, err := d.RemainingIPs()
			if err != nil {
				return d.PropErr(err)
			}
			g.TlsIPs = args
		case "ca":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			if _, err := url.Parse(args[0]); err != nil {
				return d.PropErr(err)
			}
			certmagic.DefaultACME.CA = args[0]
		default:
			return d.ArgErr()
		}
	}
	return nil
}

func loadCA(path string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ok := roots.AppendCertsFromPEM(pem)
	if !ok {
		return nil, fmt.Errorf("could not read root certificate: %s", err)
	}
	return roots, nil
}
