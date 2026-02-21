# Name

_as112_ - an AS112 black hole server

# Description

_as112_ is a AS112 black hole handler. It (if it is configured to receive those queries) replies to all
queries in the following zones with a no data response:

- 10.in-addr.arpa
- 254.169.in-addr.arpa
- 168.192.in-addr.arpa
- 16.172.in-addr.arpa
- 17.172.in-addr.arpa
- 18.172.in-addr.arpa
- 19.172.in-addr.arpa
- 20.172.in-addr.arpa
- 21.172.in-addr.arpa
- 22.172.in-addr.arpa
- 23.172.in-addr.arpa
- 24.172.in-addr.arpa
- 25.172.in-addr.arpa
- 26.172.in-addr.arpa
- 27.172.in-addr.arpa
- 28.172.in-addr.arpa
- 29.172.in-addr.arpa
- 30.172.in-addr.arpa
- 31.172.in-addr.arpa

# Syntax

```txt
as112
```

# Examples

```conffile
. {
    log
    as112
}
```

# See Also

Also see <https://www.as112.net/>.
