package dnszone

import (
	"context"
	"math"
	"path"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch watches the containing directory of file, and executes fn once a write event happens that matches file.
// Specifically it performs fn() after fsnotify.Write, fsnotify.Rename, and fsnotify.Create.
func Watch(ctx context.Context, file string, fn func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	file = path.Clean(file)
	timer := time.AfterFunc(math.MaxInt64, fn)

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					continue
				}
				switch {
				default:

				case event.Has(fsnotify.Write):
					fallthrough
				case event.Has(fsnotify.Create):
					fallthrough
				case event.Has(fsnotify.Rename):
					if file == path.Clean(event.Name) {
						timer.Reset(2 * time.Second)
					}
				}
			case _, ok := <-watcher.Errors:
				if !ok {
					continue
				}
			case <-ctx.Done():
				watcher.Close()
				return
			}
		}
	}()

	return watcher.Add(filepath.Dir(file))
}
