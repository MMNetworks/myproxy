// Copyright 2011 Miek Gieben. All rights reserved.
//
// Reflect is a small name server which sends back the IP address of its client, the recursive resolver.
// When queried for type A (resp. AAAA), it sends back the IPv4 (resp. v6) address.
// In the additional section the port number and transport are shown.
//
// Basic use pattern:
//
//	dig @localhost -p 8053 whoami.miek.nl A
//
//	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2157
//	;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//	;; QUESTION SECTION:
//	;whoami.miek.nl.			IN	A
//
//	;; ANSWER SECTION:
//	whoami.miek.nl.		0	IN	A	127.0.0.1
//
//	;; ADDITIONAL SECTION:
//	whoami.miek.nl.		0	IN	TXT	"Port: 56195 (udp)"
//
// Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
// is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
// amiopen.openresolvers.org.
//
// Original version is from: Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>.
//
// Adapted to Go (i.e. completely rewritten) by Miek Gieben <miek@miek.nl>.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"syscall"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

var (
	flagcpu   = flag.Bool("cpu", false, "write cpu profile to cpu.out")
	flagtrace = flag.Bool("trace", false, "write trace profile to trace.out")
	flagPort  = flag.Int("port", 8053, "port to listen on")
)

const dom = "whoami.miek.nl."

var hdr = &dns.Header{Name: dom, Class: dns.ClassINET}

var textPool = sync.Pool{New: func() any { return make([]byte, 0, 64) }}

func reflect(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if err := r.Unpack(); err != nil {
		log.Fatalf("%s", err.Error())
	}
	r.Reset() // re-use r
	r.Response = true

	var ip netip.Addr
	switch a := w.RemoteAddr().(type) {
	case *net.UDPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	case *net.TCPAddr:
		ip, _ = netip.AddrFromSlice(a.IP)
	}
	if ip.Is4In6() {
		ip = netip.AddrFrom4(ip.As4())
	}

	var rr dns.RR
	if ip.Is4() {
		rr = &dns.A{Hdr: *hdr, A: rdata.A{Addr: ip}}
	} else {
		rr = &dns.AAAA{Hdr: *hdr, AAAA: rdata.AAAA{Addr: ip}}
	}

	txt := textPool.Get().([]byte)
	txt = txt[:0]
	txt = append(txt, "Port: "...)
	txt = append(txt, dnsutil.RemotePort(w)...)
	txt = append(txt, " ("...)
	txt = append(txt, dnsutil.Network(w)...)
	txt = append(txt, ')')
	t := &dns.TXT{Hdr: *hdr, TXT: rdata.TXT{Txt: []string{string(txt)}}}
	textPool.Put(txt)

	switch r.Question[0].(type) {
	case *dns.TXT:
		r.Answer = append(r.Answer, t)
		r.Extra = append(r.Extra, rr)
	case *dns.AAAA, *dns.A:
		r.Answer = append(r.Answer, rr)
		r.Extra = append(r.Extra, t)
	}

	r.Pack()
	io.Copy(w, r)
}

func serve(net string) {
	addr := fmt.Sprintf("[::]:%d", *flagPort)
	server := &dns.Server{Addr: addr, Net: net, ReusePort: true, MaxTCPQueries: -1}
	if err := server.ListenAndServe(); err != nil {
		log.Printf("Failed to setup the "+net+" server: %s", err.Error())
	}
}

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

	dns.HandleFunc("miek.nl.", reflect)
	for range runtime.NumCPU() * 4 { // there is lock contention when writing back
		go serve("tcp")
		go serve("udp")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping", s)
}
