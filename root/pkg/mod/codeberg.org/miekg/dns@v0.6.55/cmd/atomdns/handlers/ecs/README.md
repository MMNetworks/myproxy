# Name

_ecs_ - add client subnet address

# Description

This handler adds the EDNS0 client subnet's (RFC 7871) subnet to the current context. If none is found, nothing
is added. Other handlers, like _geoip_ or _acl_ can use this data instead of the source IP address.

# Syntax

```txt
ecs
```

# Examples

Enable cookies:

```conffile
example.org {
    ecs
    whoami
}
```

# Context

The _ecs_ handler adds a single key to the context:

| Key        | Type         | Example      | Description  |
| :--------- | :----------- | :----------- | :----------- |
| `ecs/addr` | `netip.Addr` | 198.51.100.1 | The address. |

When the _log_ handler is used the address is automatically logged as `ecs.addr=..`.

# See Also

See RFC 7871.
