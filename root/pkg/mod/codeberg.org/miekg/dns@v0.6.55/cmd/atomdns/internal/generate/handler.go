package generate

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
)

// Handlers returns the handlers, except global and unpack.
func Handlers(path ...string) ([]string, error) {
	dir := "."
	if len(path) > 0 {
		dir = path[0]
	}

	subdirs, err := os.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}
	handlers := []string{}
	for _, d := range subdirs {
		if !d.IsDir() {
			continue
		}
		handler := dir + "/" + filepath.Join(d.Name(), d.Name()+".go")
		_, err := os.Stat(handler)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		types, err := Types(handler)
		if err != nil {
			return nil, err
		}
		// insanely crude check, but if there is a line that matches
		// 'HandlerFunc(next/_ dns.HandlerFunc) dns.HandlerFunc {' in the file it _is_ an actual handler and
		// not only a Setupper - global is skipped then for example.
		p, _ := os.ReadFile(handler)
		if bytes.Contains(p, []byte(" HandlerFunc(")) {
			handlers = append(handlers, types...)
		}
	}
	return handlers, nil
}
