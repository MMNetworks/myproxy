# Name

_whoami_ - return your resolver's local IP address, port and transport

# Description

The _whoami_ handler is not really that useful, but can be used for having a simple (fast) endpoint
to test clients against. When _whoami_ returns a response it will have your client's IP address in
the additional section as either an A or AAAA record.

The reply always has an empty answer section. The port and transport are included in the additional
section as a SRV record, network can be "tcp" or "udp".

If the _ecs_ handler added an address to the context, _that_ address is used instead.

```txt
._<network>.qname. 0 IN SRV 0 0 <port> .
```

The _whoami_ handler will respond to every A or AAAA query, regardless of the query name.

# Syntax

```txt
whoami
```

# Examples

Start a server on the default port and load the _whoami_ handler.

```conffile
example.org {
    whoami
}
```

When queried for "example.org A", atomdns will respond with:

```txt
;; QUESTION SECTION:
;example.org.   IN       A

;; ADDITIONAL SECTION:
example.org.            0       IN      A       10.240.0.1
_udp.example.org.       0       IN      SRV     0 0 40212
```
