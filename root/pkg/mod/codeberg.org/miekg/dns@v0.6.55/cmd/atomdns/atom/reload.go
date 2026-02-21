package atom

import (
	"bytes"
	"os"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/conffile"
)

func (s *Server) Reload() (err error) {
	var confdata []byte
	if builtin(s.global.Config) {
		confdata = s.config
	} else {
		if confdata, err = os.ReadFile(s.global.Config); err != nil {
			return err
		}
	}
	blocks, err := conffile.Parse(s.global.Config, bytes.NewReader(confdata))
	if err != nil {
		return err
	}

	s.global.Shutdown()
	if err := s.Setup(s.global.Config, s.global, blocks); err != nil {
		return err
	}
	return s.global.Startup()
}
