# Name

_global_ - hold global server properties

# Description

_global_ holds global server properties, like the prometheus metrics port and root directory.
It's not a handler and you can not use it as such: you can't use _global_ in the configuration, other than in the
global section, see the configuration examples below.

# Syntax

```txt
{
    root DIRECTORY
    log {
        debug
        json
        quiet
        disable
    }
    metrics [/N] [ADDRRES]
    health [ADDRESS [LAMEDUCK]]
    pprof [ADDRESS]
    dns {
        addr ADDRESS
        limits {
            tcp EXPR
            run EXPR
        }
    }
    dot {
        addr ADDRESS
        limits {
            run EXPR
        }
    }
    doh {
        addr ADDRESS
        limits {
            run EXPR
            inflight EXPR
        }
    }
    dou {
        addr SOCKET
    }
    tls ISSUER {
        cert CERT KEY
        ca URL
        source IP|IFACE [IP|IFACE]...
        contact EMAIL
        path PATH
        rootca CA
    }
}
```

- with `root` **DIRECTORY** is the directory to use as the root directory for the server. Any relative path names will
  get this directory prefixed. If **DIRECTORY** itself is also relative the current working directory (cwd) of the atomdns
  process will be prefixed.
- `log` tells atomdns on how to, globally, log:
  - `debug` sets the global log level to debug.
  - `json` enables JSON logging.
  - With `quiet` the banner is not shown. Query logging is not affected.
  - And `disable` disables the logging so that it can be enabled with the SIGUSR1 signal, see atomdns-log(7).
- The `metrics` property allows setting the listening **ADDRESS** for the promtheus metrics. This defaults to `localhost:9153`.
  Without `metrics` no metrics can be scraped as the prometheus server isn't running, i.e. to allow for
  metrics gathering `metrics` must be enabled in the global section.
  The optional **/N** tells the metric handler to monitor 1 in **N** queries. The default is 10. This needs to
  be a positive integer > 0. This is done to not impair performance too much.
  With the `metrics` handler you can enable/disable metrics on a per server basis.
- With `health` you start a local web server that exports a /health endpoint on **ADDRESS** that returns 200 OK when
  everything is OK. When **LAMEDUCK** which should be a time.Duration in string form is given, the server' shutdown will be
  delayed for that duration. The default for **ADDRESS** is `:8080`. Every 2 seconds atomdns will query itself
  to get its health so it can export the latency metrics.
- With `pprof` you can publish runtime profiling data at the endpoint on
  **ADDRESS** under `/debug/pprof`. The default is localhost:6053.

This is parsed in-order and some settings depend on `root` and/or `debug`, so set those two early in the file.

## `dns`

With `dns` you set DNS (port (usually) 53, TCP and UDP) server options, defined are.

- `addr` **ADDRESS**: listen on this address, default is `[::]:53`.
- `limits` set further limits:
  - `tcp` **LIMIT**, break off TCP connections after this many queries, default is 1024, -1 disables.
  - `run` **EXPR**, run this many servers the default is `NumCPU()*3`, this can be a bare number,
    like 5, or an expression like `NumCPU()*N`, where **N** is a whole number. `NumCPU()` may be spelled in
    lowercase, i.e. `numcpu()*N` is OK. Note that adding more servers helps with lock contention when writing the DNS messages
    back to the client. This number is again multiplied by 2 for 50% UDP, and 50% TCP server. So `run 5`, will
    start 10 server instances. The maximum value is the number of CPUs \* 1024.

## `dot`

With `dot` you control DNS TLS server options, defined are.

- `addr` **ADDRESS**: listen on this address, default is `[::]:853`.
- `limits` set further limits:
  - `tcp` **LIMIT**, break off TCP connections after this many queries, default is 1024, -1 disables.
  - `run` **EXPR**, run this many servers the default is `NumCPU()*1`, this can be a bare number,
    like 5, or an expression like `NumCPU()*N`, where **N** is a whole number. `NumCPU()` may be spelled in lowercase.
    These are all TCP servers, so `run 5` will start 5 servers, not 10 as would the case with `dns`.

This requires a `tls` setup too.

## `doh`

With `doh` you set HTTP server options, defined are.

- `addr` **ADDRESS**: listen on this address, default is `[::]:443`.
- `limits` set further limits:
  - `run` **EXPR**, run this many servers the default is `NumCPU()*1`, this can be a bare number,
    like 5, or an expression like `NumCPU()*N`, where **N** is a whole number. `NumCPU()*` may be spelled in lowercase.
  - `inflight` **EXPR**, like `run`, how many inflight connection are we allowing, default is 1024, -1 disables.

To allow the certificate challenge, all DOH HTTP servers will also handle the TLS-ALPN-1 challenge,
disregarding the port the run on. If the DOH servers are not running on port 443, one extra server will be
started on that port, _just_ for the certificate challenge. N.B. This is only done if the port isn't "0",
because that is usually used in testing scenarios. This requires the atomdns binary to be able to bind to that
port.

This requires a `tls` setup too.

## `dou`

With `dou` you configure an Unix domain socket to listen on, defined are.

- `addr` **SOCKET**: listen on this Unix domain socket. Note there are OS limits on the length of the socket's file name.
  If this is a relative name the path from `root` will be prepended.

Querying over a Unix domain socket needs to be done using the TCP packet format, for example:
`kdig +tcp www.example.org @/tmp/dns.sock`, if **SOCKET** is set to `/tmp/dns.sock`.

## `tls`

With `tls` you configure the TLS certificate setup. **ISSUER** can be `manual`, or `lets-encrypt`. The later
will set up the certicates automatically. If you use relative path in this configuration be sure that `root`
is set _above_ this config, so that its value is set.

Depending on **ISSUER**, you have the following further configuration:

If **ISSUER** is `manual`:

- `cert`, that lists in that order **CERT** the `cert.pem` (as an example name) file, **KEY** the private key,
  `key.pem`
- `rootca`, the root `ca.pem` file. This is optional, but can aid in testing.

If **ISSUER** is `lets-encrypt`:

- `source`, a list of **IP**s or **IFACE** names for which the IP addresss should be retrieved, and for which
  the TLS certificates should be requested.
- `contact`, where **EMAIL** is the contact email use when retrieving certificates. This can be set to (one
  of) your SOA's Mbox (RNAME - responsible person) mail address.
- `path` has the **PATH** where the certificates are stored. The global's `root` is prepended if this a
  relative path name.
- `ca` lets you select the production or staging ACME CA endpoint, by specifying the URL here. The default for
  the time being is Let's Encrypt staging endpoint: <https://acme-staging-v02.api.letsencrypt.org/directory>.
  The production endpoint for Let's Encrypt is <https://acme-v02.api.letsencrypt.org/directory>.
  If after the URL the literal text `test` is used, atomdns will not start a seperate web server on port 443,
  this is to aid in local testing.
- `rootca`, can also be used here. This is optional, but can aid in testing.

Both `source` and `contact` are mandatory.

To complete the challenge a web server needs to be running on port 443, if DOH is enabled (see `doh`), and is
not already running on 443 another server will be started on that port just for the challenge.

# Examples

This runs both a DNS and DOH server, the DOH server listens on port 8053.

```txt
{
    root /var/lib/atomdns
    metrics localhost:9153
    tls lets-encrypt {
        contact hello@example.org
        source eth0
        path certs
    }
    dns {
        limits {
            tcp -1
            run NumCPU()*3
        }
    }
    doh {
        addr [::]:8053
    }
}

example.org {
    log
    whoami
}
```

Or run an health endpoint on http://localhost:8091, with a lame-duck delay of 200 ms.

```txt
{
    health localhost:8091 200ms
}
```

# Metrics

If monitoring is enabled (via `metrics`) and `health` is enabled the following metrics are exported:

- `atomdns_health_request_duration_seconds{}` - `health` performs a self health check
  once per second on the `/health` endpoint. This metric is the duration to process that request.
  As this is a local operation it should be fast. A (large) increase in this
  duration indicates the atomdns process is having trouble keeping up with its query load.
- `atomdns_health_request_failures_total{}` - The number of times the self health check failed, this also
  points to imminent failure.
