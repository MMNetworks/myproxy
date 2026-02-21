package template

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"text/template"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (t *Template) Setup(co *dnsserver.Controller) (err error) {
	if co.Next() {
		if !co.NextArg() {
			return co.ArgErr()
		}
		if len(co.Val()) > 1000 {
			return co.PropErr(errors.New("regexp too large"))
		}
		t.Regexp, err = regexp.Compile(co.Val())
		if err != nil {
			return err
		}

		types := co.RemainingArgs()
		for _, ty := range types {
			if j, ok := dns.StringToType[ty]; !ok {
				return co.PropErr(fmt.Errorf("%q is not a type", ty))
			} else {
				t.Types = append(t.Types, j)
			}
		}

		if co.NextBlock(0) {
			t.Path = co.Path()
		}
	}
	if t.Path == "" {
		return fmt.Errorf("no template path")
	}
	co.OnStartup(func() error {
		log().Info("Startup", "executing", filepath.Base(t.Path))
		tmpl, err := template.ParseFiles(t.Path)
		if err != nil {
			return err
		}
		buf := &bytes.Buffer{}
		return tmpl.Execute(buf, &Data{})
	})
	return nil
}
