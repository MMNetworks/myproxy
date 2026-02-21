# atomdns

atomdns is a DNS server/router, written in Go, that chains handlers. Each handler performs a (DNS) function.
Its architecture is identical to HTTP servers with middleware. The order of the handlers in the configuration
determines the order in which they are executed. (If you know CoreDNS; you might know that it has a fixed
order - atomdns is _different_).

atomdns is a rock-solid replacement for CoreDNS, BIND9, Knot, NSD, etc. This is not a toy example on how to
use the dns library. atomdns is a fast and flexible DNS server. The key word here is _flexible_: with atomdns
you are able to do what you want with your DNS data by utilizing handlers. If some functionality is not
provided out of the box, you can add it by writing a handler.

But why another server? Personally I felt that CoreDNS went all "the cloud way", without properly laying the
basis for a DNS server that I want to run at home, there was also a lot of code duplication that was solved by
writing miekg/dnsv2. And I needed a server to develop miekg/dnsv2 in tandem with the library.

See <https://atomdns.miek.nl> for more complete docs.

atomdns can:

- Serve zone data from a file; with DNSSEC support (_dbfile_), plus:
  - Zone transfers and notifies.
  - DNSSEC signing (_sign_).
- Provide query logging (_log_).
- Access control for queryes (_acl_).
- Provide metrics (by using Prometheus) (_metrics_).
- Serve from a SQLite database (_dbsqlite_).
- ... and more.
- Serve as a router to router queries to some other (recursive) nameserver (_route_). [TODO]

Each of these handlers has its own manual page, i.e. see atomdns-dbfile(7) for more information on the
_dbfile_ handler for instance. These are generated from the (extensive) READMEs each handler must have.

## Compilation from Source

To compile atomdns, we assume you have a working Go setup. See various tutorials if you don’t have that
already configured. We follow upstream Go closely and use new language features when they come available.

```
$ git clone https://codeberg.org/miekg/dns
$ cd dns/cmd/atomdns
$ go build
```

This should yield a `atomdns` binary.

## Examples

The configuration of atomdns is done through a file named `Conffile`. When atomdns starts, it will look for
the `Conffile` from the current working directory. A `Conffile` for atomdns server that listens on port `1053`
and enables `whoami` handler is:

```conffile
{
    dns {
        addr [::]:1053
    }
}

. {
    whoami
}
```

Then start `./atomdns -c Conffile`.

Or use `Conffile-example` which has a more complete setup.

    ./atomdns -c Conffile-example

When atomdns starts you are greeted (when not using `quiet`) a bunch of log lines and a welcome banner:

```txt
2025/12/18 13:30:03 INFO 0.0.10.in-addr.arpa. handlers=log,whoami
2025/12/18 13:30:03 INFO example.org. handlers=id,log,dbfile
2025/12/18 13:30:03 INFO miek.nl. handlers=log,metrics,sign,dbfile
2025/12/18 13:30:03 INFO Startup functions total=14
2025/12/18 13:30:03 INFO Startup handler=global /health=:8080
2025/12/18 13:30:03 INFO Startup handler=global health="overload check"
2025/12/18 13:30:03 INFO Startup handler=global /metrics=localhost:9153 /N=10
2025/12/18 13:30:03 INFO Startup handler=global dns=[::]:1053 tcp=-1 run=24
2025/12/18 13:30:03 INFO Startup handler=global doh=[::]:1443 run=8 inflight=100 path=/dns-query
2025/12/18 13:30:03 INFO Startup handler=global dot=[::]:8053 tcp=1024 run=1 inflight=200
2025/12/18 13:30:03 INFO Startup handler=global tls=manual
2025/12/18 13:30:03 INFO Startup handler=global signal=HUP
2025/12/18 13:30:03 INFO Startup handler=log signal=USR1
2025/12/18 13:30:03 INFO Startup handler=dbfile reload=db.example.org
2025/12/18 13:30:03 INFO Startup handler=sign signing=db.miek.nl
2025/12/18 13:30:03 INFO Days left before expiration handler=sign zone=miek.nl. path=db.miek.nl.signed days=36
2025/12/18 13:30:03 INFO Startup handler=dbfile reload=db.miek.nl.signed
2025/12/18 13:30:03 INFO Build GOOS=linux GOARCH=arm64 go=1.25.5 revision=79e3ca30a4364da296eb74ab67ae04a184166e5a
2025/12/18 13:30:03 INFO Listening roles=DNS:[::]:1053,DOH:[::]:1443,DOT:[::]:8053
2025/12/18 13:30:03 INFO Launched config=Conffile-example PID=3325169 version=v058 dns=0.6.5 zones=3
  ┏━┓  ╺┳╸  ┏━┓  ┏┳┓
  ┣━┫   ┃   ┃ ┃  ┃┃┃  DNS
  ╹ ╹   ╹   ┗━┛  ╹ ╹ v058 (0.6.5)
  High performance and flexible DNS server
  https://atomdns.miek.nl
__________________________________\o/_______
```

Where the last INFO lines shows the config parsed, the number of origins processed and for which protocols the
server can answer, here: DNS, DOH (DNS over HTTPS) and DOT (DNS over TLS) and on which ports.

See atomdns-conffile(7) for more information. For a more total experience head over to
<https://atomdns.miek.nl>.
