# Converting from v1 to v2

## What changed?

A lot. See below.

## General tips

None of these are required but experience has proven them to be good ideas.

1.  Convert to netip.Addr first.
    Before you convert to dns v2, convert from `net.IP` to `netip.Addr`. DNS v2
    uses `netip.Addr` to represent IP addresses. Converting two modules at the same
    time is much more difficult than converting them in sequence.

2.  Make v1 and v2 coexist, then work to eliminate v1
    If you make v1 and v2 coexist your conversion will be easier. You can work incrementally
    instead of one big "big bang" change. You can identify code that needs to be upgraded
    by searching for `dnsv1.`

    Code that uses both will have imports that look like:

    ```go
        import (
            dnsv1 "github.com/miekg/dns"
            "codeberg.org/miekg/dns"
        )
    ```

    Here's how to do it:

    Rename v1 to dnsv1

    Change all imports from

        "github.com/miekg/dns"

    to

        dnsv1 "github.com/miekg/dns"

    Now v1 and v2 can co-exist. `dnsv1.RR` is the old code and `dns.RR` is the new code.

    You might consider shipping a release that has this one change. This should be a "no op" change
    and therefore no tests should fail, no features should break. Now you have a baseline
    before other changes are made.

    ProTip: VSCode makes this easy. Find code that mentions `dns.` and use "Rename Symbol" (F2) to change it
    to `dnsv1.`. VSCode does all the work of finding all instances. It even updates the imports line. You'll
    need to do this once for each file. VSCode is smart enough to know that imports are per-file, even though
    Rename Symbol can work across multiple files.

    Find the files that need this change:

        grep -l -R -r --include='*.go' github.com/miekg/dns

3.  Do this for _dnsutil_ and other packages

    Do something similar for _dnsutil_ (_dnsutilv1_) also. Again, this isn't required, just useful.

4.  Work incrementally

    It's best to convert a little, test, convert a little more, test, etc. Trying to convert
    everything makes testing difficult.

    Doing this requires you to be able to convert between v1's `RR` and v2's `RR`.

    Here are some conversion functions. The functions are slow and ugly, but accuracy is more important. (The
    functions being slow is OK because they are temporary. The slowness should give you incentive to finish
    porting to v2!

    ```go
    package dnsrr

    import (
            dnsv2 "codeberg.org/miekg/dns"
            dnsv1 "github.com/miekg/dns"
    )

    // RRv1tov2 converts github.com/miekg/dns (v1) RR to codeberg.org/miekg/dns (v2) RR.
    // Typically used in providers that still use v1.
    // Note: this function is not efficient. It converts via string representation.
    // Use it until you are able to convert to v2 fully.
    // Note: Panics on error.
    func RRv1tov2(rrv1 dnsv1.RR) dnsv2.RR {
            rrv2, err := dnsv2.New(rrv1.String())
            if err != nil {
                    panic("Failed to convert RR to v2: " + err.Error())
            }
            return rrv2
    }

    // RRv2tov1 converts codeberg.org/miekg/dns (v2) RR to github.com/miekg/dns (v1) RR.
    // Typically used in providers that still use v1.
    // Note: this function is not efficient. It converts via string representation.
    // Use it until you are able to convert to v1 fully.
    // Note: Panics on error.
    func RRv2tov1(rrv2 dnsv2.RR) dnsv1.RR {
            rrv1, err := dnsv1.NewRR(rrv2.String())
            if err != nil {
                    panic("Failed to convert RR to v1: " + err.Error())
            }
            return rrv1
    }
    ```

# Difference with github.com/miekg/dns

I have ported a few utilities from dnsv1 to dnsv2, and dnsv2 is mostly a drop-in replacement. Of course YMMV.

- Many functions (and new ones) are moved into _dnsutil_, and _dnstest_. This copied a lot of stuff from CoreDNS.
- _dnshttp_ was added for help with DOH - DNS over HTTPs.
- `RR` lost the `Type` and `Rdlength` fields, type is derived from the Go type, `Rdlength` served no function at all.
  The `Header` is thus 4 bytes smaller than in v1. The RFC3597 (unknown RRs) has gained a `Type` field because of this.
- The rdata of each `RR` is split out in to a _rdata_ package. This makes it much more memory efficient to
  store RRSets - as the RR's header isn't duplicated. This saves a minimal of 24 bytes (empty string, ttl, and
  class) per RR stored.
- `context.Context` is used in the correct places. `ServeDNS` now has a context.Context, with `Zone(ctx)` you
  retrieve the pattern zone that lead to invocation of this Handler.
- _internal/..._ packages that hold code that used to be private, but was cluttering the top level directory; also allowed for better
  naming.
  - builtin perf testing with _internal/dnsperf_. Need `dnsperf`, on deb-based systems `apt-get install dnsperf`.
- Interfaces do not have private methods.
- No more `dns.Conn`.
- `Msg` contains a buffer named `Data` that holds the binary data for this message. This pulls TSIG/SIG(0)
  handling out of the client and server, simplifying it enormously as we can get rid of `dns.Conn`, and just
  use io.Writer and io.Reader interfaces.
- `Msg` includes `Options` that control on how you want it packed/unpacked.
- `Msg` includes all the ENDS0 OPT RR bits, as this almost was a real message header; in this package it now is.
- `Msg` has a pseudo section that holds all EDNS0 Options as (faked) resource records.
- Everything is a resource record:
  - question section: holds `[]RR`
  - pseudo section: holds `[]RR`
  - stateful section: holds `[]RR`

  Pseudo section RR (EDNS0 OPT) can also be parsed from their (also unique to this library) presentation format.

  The `Stateful` section in the message that holds DNS Stateful Operation (DSO) records, these records are
  also `RR`s. (The Stateful section was unused - this has been removed from Msg for the time being).

- `New` will return an `RR`, `NewRR` is gone, `dnstest/New` will do the same, but panic on errors.
- `Client` has a `dns.Transport` just like `http.Client`, so _all_ connection management is now external.
- More:
  - `Msg` is a io.Writer.
  - `msg.Data` can be re-used between request and reply in Exchange.
  - `msg.Data` can be returned to a server buffer pool, for reuse in new messages, this is done automatically,
    see `msg.Hijack()` for hijacking the buffer.
  - private RRs are easier.
  - private EDNS0 are implementable and hopefully easier.
- SVCB record got its own package _svcb_ where all the key-values (called `svcb.Pair`) now reside.
- DELEG record also got its own package _deleg_, where its key-values (called `deleg.Info`) live.
- IsDuplicate is gone in favor of Compare and a full support for the `sort.Interface`, so you can just
  sort RRs in an RRset. This also simplified the DNSSEC signing and make wireformat even less important.
- Copied, sanitized and removed tests that accumulated over 16 years of development.
- Escapes in domain names is not supported. This added 50-100% overhead in low-level functions that are often
  used in the hot path. In rdata (TXT records) it still is.
- The less used ClientConfig now lives in _dnsconf_.

# Converting idioms

Here are some v1 vs v2 changes.

Please add to this list! The conversions you find will be useful to others. Please submit a PR to this file!

## RRs

Create an RR.

```
OLD                                                                  | NEW
                                                                     |
r := &MX{ Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600},  | r := &MX{
        Preference: 10, Mx: "mx.miek.nl."}                           |   Header{Name:"miek.nl.", Class: dns.ClassINET, TTL: 3600},
                                                                     |   MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."},
                                                                     | }
```

Print RR without header.

```
OLD                                                        | NEW
                                                           |
mx, _ := dns.NewRR("miek.nl. 3600 IN MX 10 mx.miek.nl.")   | mx := dnstest.New("miek.nl. 3600 IN MX 10 mx.miek.nl.")
hdr := mx.Header().String()                                | hdr := mx.Header().String()
flds := mx.String()[len(hdr)+1:]                           | fmt.Printf("Fields: %q\n", mx.MX.String())
fmt.Printf("Fields: %q\n", flds)                           |
```

Access RR's rdata.

```
OLD                                                        | NEW
                                                           |
mx, _ := dns.NewRR("miek.nl. 3600 IN MX 10 mx.miek.nl.")   | mx := dnstest.New("miek.nl. 3600 IN MX 10 mx.miek.nl.")
num := dns.NumField(mx)                                    | rdata := mx.MX
for i := range num {                                       | rdata.Preference = 10
    fmt.Printf("%q", dns.Field(i))                         |
}                                                          |
```

What type is this RR and as string.

```
OLD                                 | NEW
                                    |
hdr := rr.Header()                  | rrtype := dns.RRToType(rr)
rrtype := hdr.Rrtype                | str := dns.TypeToString[rrtype]
str := dns.TypeToString[rrtype]     | // or
                                    | str = dnsutil.TypeToString(rrtype) // gives TYPEXXX for unknown types
```

Find the TTL:

```
OLD                 | NEW
                    |
rr.Header().Ttl     | rr.Header().TTL
```

## Setting EDNS0

```
OLD                                           | NEW
                                              |
m := new(dns.Msg)                             | m := dns.NewMsg("miek.nl.", dns.TypeDNSKEY)
m.SetQuestion("miek.nl.", dns.TypeDNSKEY)     | m.UDPSize, m.Security = 4096, true
m.SetEdns0(4096, true)                        |
                                              | // or
                                              |
                                              | m := new(dns.Msg)
                                              | dnsutil.SetQuestion(m, "miek.nl.", dns.TypeDNSKEY")
                                              | m.UDPSize, m.Security = 4096, true
```

Setting the UDP buffer size.

```
OLD                                                      | NEW
                                                         |
bufsize := 0                                             | bufsize := m.UDPSize
for i := len(m.Extra) - 1; i >= 0; i-- {                 |
    if m.Extra[i].Header().Rrtype == dns.TypeOPT {       |
		bufsize = m.Extra[i].(*dns.OPT).UDPSize()        |
    }                                                    |
}                                                        |
```

Accessing ENDS0 options.

```
OLD                                                      | NEW
                                                         |
opt := 0                                                 | for i, options := range m.Pseudo {
for i := len(m.Extra) - 1; i >= 0; i-- {                 |     // ...
	if m.Extra[i].Header().Rrtype == dns.TypeOPT {       | }
	opt = m.Extra[i].(*dns.OPT)|                         |
    }                                                    |
}                                                        |
for i, options := range opt.Options {                    |
    // ...                                               |
}                                                        |
```

Checking if there _is_ an EDNS0 option added.

```
OLD                                                      | NEW
                                                         |
x := m.IsEdns0()                                         | x := len(m.Pseudo) > 0
                                                         | // The OPT RR itself is incorperated into Msg.
```

Adding an EDNS0 option is just as easy, assign to the pseudo section.

```
OLD                                                               | NEW
                                                                  |
o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}} |
o.SetDo()                                                         | m.Security = true
o.SetUDPSize(dns.DefaultMsgSize)                                  | m.UDPSize = dns.DefaultMsgSize
e := &dns.EDNS0_NSID{Code: dns.EDNS0NSID}                         | m.Pseudo = append(m.Pseudo, &dns.NSID{})
o.Option = append(o.Option, e)                                    |
m.Extra = append(m.Extra, o)                                      |
```

## Msg

Ranging over an entire `Msg`:

```
OLD                     | NEW
                        |
// N/A                  | for rr := range m.RRs() { ... }
```

Set the EDNS0 UDP buffer size:

```
OLD                                                               | NEW
                                                                  |
m := new(dns.Msg)                                                 | m := dns.NewMsg("miek.nl.", dns.TypeDNSKEY)
m.SetQuestion("miek.nl.", dns.TypeDNSKEY)                         | m.UDPSize, m.Security = 4096, true
o.SetEdns0(4096, true)                                            |
```

## Text Output

Note the `do` flag now being shown as if it was set in the message header, OPT options are displayed as RRs
and can also be created with `dns.New`.

```
OLD                                                                  | NEW
                                                                     |
;; opcode: QUERY, status: NOERROR, id: 62167                         | ;; QUERY, rcode: NOERROR, id: 3, flags: rd do
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0 | ;; EDNS, version: 0, udp: 1024
                                                                     | ;; QUESTION: 1, PSEUDO: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0, DATA SIZE: 25
;; OPT PSEUDOSECTION:                                                |
; EDNS: version 0; flags:; udp: 512                                  | ;; PSEUDO SECTION:
; NSID: 6770646e732d616d73  (g)(p)(d)(n)(s)(-)(a)(m)(s)              | .               CLASS0  NSID    6770; "gpdns-ams"
                                                                     |
;; QUESTION SECTION:                                                 |
;miek.nl.       IN       MX                                          | ;; QUESTION SECTION:
                                                                     | miek.nl.                IN      A
```

## Functions and Methods

```
OLD                   | NEW
                      |
r := m.Copy()         | r := m.Copy() // Shallow copy!
```

Fqdn has moved.

```
OLD                   | NEW
                      |
s := dns.Fqdn(s)      | s := dnsutil.Fqdn(s)
```

SetQuestion has moved.

```
OLD                                           | NEW
                                              |
m.SetQuestion("miek.nl.", dns.TypeDNSKEY)     |  dnsutil.SetQuestion(m, "miek.nl.", dns.TypeDNSKEY)
```

CanonicalName has moved and been renamed.

```
OLD                                | NEW
                                   |
canon := dns.CanonicalName(name)   | canon := dnsutil.Canonical(name)
```

## Server

Because `Msg` now carries its binary data too there is no need to do TSIG in the server it self, it can now be
done in a handler. This, again, removes a little of internal code that slowed things down.

The default implementation of `dns.ResponseWriter` is thread safe and this for TCP pipe lining, which is thusly
implemented in `dns.Server`. Writing or reading data is now done with `io.Copy` no more `ReadMsg` or `WriteMsg`.

A handler for instance.

```
OLD                                                      | NEW
                                                         |
func HelloServer(w dns.ResponseWriter, req *dns.Msg) {   | func HelloServer(ctx contect.Context, w ResponseWriter, req *Msg) {
	m := new(dns.Msg)                                    |     m := req.Copy()
	m.SetReply(req)                                      |     dnsutil.SetReply(m, req)
                                                         |
	m.Extra = make([]dns.RR, 1)                          |     m.Extra = []dns.RR{
	m.Extra[0] = &TXT{                                   |         &TXT{Hdr: dns.Header{Name: m.Question[0].Name, Class: dns.ClassINET},
        Hdr: dns.RR_Header{Name: m.Question[0].Name,     |              Txt: []string{"Hello world"}}
        Rrtype: dns.TypeTXT, Class: dns.ClassINET},      |     }
        Txt: []string{"Hello world"}                     |
    }                                                    |     m.Pack()
	w.WriteMsg(m)                                        |     io.Copy(w, m)
}                                                        | }
```

## Zone Parser

Allow includes.

```
OLD                                        | NEW
                                           |
 zp := dns.NewZoneParser(...)              | zp := dns.NewZoneParser(...)
 zp.SetIncludeAllowed(true)                | // now the default
```

Disallow includes.

```
OLD                                        | NEW
                                           |
 zp := dns.NewZoneParser(...)              | zp := dns.NewZoneParser(...)
 zp.SetIncludeAllowed(false)               | zp.IncludeAllowFunc = func() bool { return false }
```
