package handlers_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeberg.org/miekg/dns/cmd/atomdns/atomtest"
)

// TestReadme parses all README.mds of the handler and checks if every example Conffile.
// actually works. Each conffile snippet is only used if the language is set to 'conffile':
//
// ~~~ conffile
//
//	. {
//		# check-this-please
//	}
//
// ~~~
// To skip the check use txt as the language.
func TestReadme(t *testing.T) {
	dirs, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		readme := filepath.Join(d.Name(), "README.md")
		t.Logf("Testing %s", readme)

		confs, err := confFromReadme(readme)
		if err != nil {
			continue
		}

		t.Logf("Testing %s: %d snippets found", readme, len(confs))
		for _, conf := range confs {
			_, cancel, err := atomtest.New(conf)
			if err != nil {
				if strings.Contains(err.Error(), "no such file or directory") {
					// parsing went far enough to this this, think we're ok
					continue
				}
				if strings.Contains(err.Error(), "failed to find routable IP") {
					// same
					continue
				}
				t.Errorf("Failed to start server with %s, for input %q:\n%s", readme, err, conf)
				continue
			}
			cancel()
		}
	}
}

// confFromReadme parses a readme and returns all fragments that
// have ~~~ conffile (or ``` conffile), it's a pretty crude parser.
func confFromReadme(readme string) ([]string, error) {
	f, err := os.Open(readme)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	conffile := false
	temp := ""
	confs := []string{}

	for s.Scan() {
		line := s.Text()
		if line == "~~~conffile" || line == "```conffile" {
			conffile = true
			continue
		}
		if line == "~~~ conffile" || line == "``` conffile" {
			conffile = true
			continue
		}

		if conffile && (line == "~~~" || line == "```") {
			// last line
			confs = append(confs, temp)
			temp = ""
			conffile = false
			continue
		}

		if conffile {
			temp += line + "\n" // read newline stripped by s.Text()
		}
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return confs, nil
}
