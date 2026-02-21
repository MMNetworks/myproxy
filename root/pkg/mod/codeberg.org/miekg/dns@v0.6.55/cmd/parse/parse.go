package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"runtime/trace"
	"time"

	"codeberg.org/miekg/dns"
)

var (
	flagcpu   = flag.Bool("cpu", false, "write cpu profile to cpu.out")
	flagtrace = flag.Bool("trace", false, "write trace profile to trace.out")
	flagprint = flag.Bool("print", false, "write each RR to standard output")
)

func main() {
	flag.Parse()

	if *flagtrace {
		f, err := os.Create("trace.out")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		trace.Start(f)
		defer trace.Stop()
	}

	if *flagcpu {
		f, err := os.Create("cpu.out")
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	buf, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	z := bytes.NewReader(buf)
	zp := dns.NewZoneParser(z, ".", flag.Arg(0))
	i := 0
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if *flagprint {
			fmt.Println(rr.String())
		}
		i++
	}
	if zp.Err() != nil {
		log.Fatal(zp.Err())
	}
	fmt.Printf("time = %.2fs, RRs = %d, RRs/s = %.2f\n", time.Since(now).Seconds(), i, float64(i)/time.Since(now).Seconds())
}
