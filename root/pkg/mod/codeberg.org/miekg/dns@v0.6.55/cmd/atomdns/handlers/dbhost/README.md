# Name

_dbhosts_ - serve data from /etc/hosts

# Description

The _dbhost_ handler is useful for serving data from a `/etc/hosts` file. It watches the file and reloads it
when written to. The _dbhost_ handler can only reply to A, AAAA and PTR queries, all others are deferred to
the next handler(s).

The _dbhost_ handler can be used with readily available hosts files that block access to advertising servers.

# Hosts File

Commonly the entries are of the form `IP_address canonical_hostname [aliases...]` as explained by
the hosts(5) man page.

Examples:

```
# The following lines are desirable for IPv4 capable hosts
127.0.0.1       localhost
192.168.1.10    example.com            example

# The following lines are desirable for IPv6 capable hosts
::1                     localhost ip6-localhost ip6-loopback
fdfc:a744:27b5:3b0e::1  example.com example
```

## Reverse Lookups

PTR records for reverse lookups are generated automatically.

# Syntax

```txt
dbhost [FILE] {
    ttl TTL
}
```

- **FILE** the hosts file to read and parse. If the path is relative the path from the _root_
  handler will be prepended to it. Defaults to`/etc/hosts` if omitted.
- `ttl` change the **TTL** of the records generated (forward and reverse). The default is 3600 seconds (1 hour).

# Examples

Load `/etc/hosts` file.

```conffile
. {
    dbhost
}
```

Load `example.hosts` file in the current directory (if _root_ is not set), and only use it for `example.org`
names:

```
example.org {
    dbhost example.hosts
}
```

# See Also

The form of the entries in the `/etc/hosts` file are based on IETF [RFC
952](https://tools.ietf.org/html/rfc952) which was updated by IETF [RFC
1123](https://tools.ietf.org/html/rfc1123).
