package drunk

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"codeberg.org/miekg/dns/cmd/atomdns/internal/dnsserver"
)

func (d *Drunk) Setup(co *dnsserver.Controller) error {
	d.drop = 4
	drop := false
	for co.Next() {
		for co.NextBlock(0) {
			switch co.Val() {
			case "drop":
				drop = true
				args := co.RemainingArgs()
				if len(args) > 1 {
					return co.ArgErr()
				}

				if len(args) == 0 {
					continue
				}
				if !strings.HasPrefix(args[0], "/") {
					return co.PropErr(fmt.Errorf("no / found"))
				}
				drop, err := strconv.ParseInt(args[0][1:], 10, 32)
				if err != nil || drop < 0 {
					return co.PropErr(fmt.Errorf("not a (positive) number: %q", co.Val()[1:]))
				}
				d.drop = uint64(drop)
			case "delay":
				args := co.RemainingArgs()
				if len(args) > 2 {
					return co.ArgErr()
				}

				d.delay = 2
				d.duration = 100 * time.Millisecond
				if len(args) == 0 {
					continue
				}

				if !strings.HasPrefix(args[0], "/") {
					return co.PropErr(fmt.Errorf("no / found"))
				}
				delay, err := strconv.ParseInt(args[0][1:], 10, 32)
				if err != nil || delay < 0 {
					return co.PropErr(fmt.Errorf("not a (positive) number: %q", args[0][1:]))
				}
				d.delay = uint64(delay)

				if len(args) > 1 {
					duration, err := time.ParseDuration(args[1])
					if err != nil {
						return err
					}
					d.duration = duration
				}
			case "truncate":
				args := co.RemainingArgs()
				if len(args) > 1 {
					return co.ArgErr()
				}

				d.truncate = 4
				if len(args) == 0 {
					continue
				}

				truncate, err := strconv.ParseInt(args[0][1:], 10, 32)
				if err != nil || truncate < 0 {
					return co.PropErr(fmt.Errorf("not a (positive) number: %q", co.Val()[1:]))
				}
				d.truncate = uint64(truncate)
			default:
				return co.PropErr()
			}
		}
	}
	if (d.delay > 0 || d.truncate > 0) && !drop { // delay is set, but we've haven't seen a drop keyword, remove default drop stuff
		d.drop = 0
	}
	return nil
}
