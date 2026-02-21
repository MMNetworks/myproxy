# Name

_dbfile_ - serve zone data from an RFC 1035-style file

# Description

The _dbfile_ handler is used for DNS servers that serve from a file that loaded from disk,
containing RFC 1035 styled data. If the zone file contains signatures (i.e., is signed using DNSSEC), correct
DNSSEC answers are returned. Only NSEC is supported. See the _sign_ handler if you want to sign and resign your
zone automatically.

The server will reply with minimal responses by default. The _dbfile_ handler will watch the zone file and when
it receives a (kernel) notify it will reload the zone after 2 seconds. Regardless of any change it will send out
notifies if configured to do so, the actual SOA serial isn't relevant.

# Syntax

In it simplests form _dbfile_ you can use:

```
dbfile FILE
```

- **FILE** the zone file to load. If the path is relative, the path from the global root config will be
  prepended to it.

If the handler block contains multiple zones, they all will use the _same_ **FILE**. And you must make
sure that zone **FILE** is generic enough, i.e. use `@` for origins instead of domain names. Note that this break
incoming transfers and thus will lead to an error when attempted.

For extra control you can open the block and define multipe extra properties that deal with zone transfers.

```
dbfile FILE {
    transfer {
        from IP[:PORT] [IP[:PORT]]... {
            key NAME ALGORITHM SECRET
        }
        to [IP[:PORT]]... {
            notify IP[:PORT] [IP[:PORT]]...
            source IP|IFACE [IP|IFACE]
            key NAME ALGORITHM SECRET
        }
    }
}
```

- `transfer` details how zone transfers are handled, `from` deals with incoming AXFR from **IP**, and `to`
  deals with outgoing ones. Without `transfer` all transfers are prohibited. When transfer from a secondary
  _all_ SOA timers are ignored, every 10 time minutes the upstream(s) is(/are) check for SOA updates.
  - `from` allows for multiple upstream **IP**s to be specified, they will be tried in that order. Notifies
    from those servers will be matched against **IP**s.
    If `from` is used _multipe_ zones are disallowed, and will cause an error because the transferred zone
    cant be shared. To save the zone file the directory of **FILE** must be writeable.
  - The `key` specification is for TSIG signed transfers. The **SECRET** must be base64 encoded.
  - `to` allows for multipe downstream **IP**s to be specified, those are all allowed to initiate a transfer.
    If there are no **IP**s specfied the AXFR is open to the entire internet.
  - If there is no `notify` the **IP**s as specified in `to` are used for sending notifies. If you
    want to override this add a `notify` and put an (new) set of **IP**s there. There can be at the most two
    IPs here, one for IPv4 and one for IPv6. With `source` you can set the source(s) address when sending the
    notifies. You can use an interface name as **IFACE** and the routable IP address from the interface are also
    used. The TSIG key specification is identical to that of `from`. For **IP** you can use IPv6 or IPv4
    addresses, these are automatically matched up, i.e. a notify with a IPv4 address will use a IPv4 source and
    vice versa.

Note that a bare `transfer` is enough to allow for outgoing transfers.

# Examples

Load the `example.org` zone from `db.example.org` and allow transfers to the internet, but send
notifies to 10.240.1.1

```conffile
example.org {
    dbfile db.example.org {
        transfer {
            to {
                notify 10.240.1.1
            }
        }
    }
}
```

Where `db.example.org` would contain RRs in the (text) presentation format from RFC 1035:

```
$ORIGIN example.org.
@	3600 IN	SOA sns.dns.icann.org. noc.dns.icann.org. 2017042745 7200 3600 1209600 3600
	3600 IN NS a.iana-servers.net.
	3600 IN NS b.iana-servers.net.

www     IN A     127.0.0.1
        IN AAAA  ::1
```

Or use a single zone file for multiple zones:

```conffile
example.org example.net {
    dbfile example.org.signed {
        transfer {
            to 10.240.1.1 {
                source eth0
            }
        }
    }
}
```

# See Also

See the _sign_ handler for signing your zones and see RFC 1035 for more info on how to structure zone files.
