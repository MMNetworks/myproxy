# Name

_log_ - log queries

# Description

By just using _log_ you dump all queries on standard output. Note that for busy servers logging will incur a
performance hit. The _log_ handler only logs properties of the incoming query.

Enabling or disabling the _log_ handler only affects the query logging, any other logging from atomdns will
show up regardless.

The logging of a running server can be toggled by sending the processs a SIGUSR1 signal. This is a process
wide toggle, all logging of all servers is enabled or disabled.

When outputting a log line, _log_ will seach for `ecs/addr` and `id/id` in the context and will add the
values to the log when found.

# Syntax

```txt
log
```

Or optionally if you want to log non-default values from the context:

```txt
log {
    CTX
    [CTX]...
}
```

Where:

- **CTX** is a context key like `geoip/city`. A non-existing context key is silently ignored. Adding default
  keys (`ecs/addr` and `id/id`) will error.

A typical example looks like this:

```txt
2025/10/06 07:25:52 INFO example.org. network=udp remote=::1 port=40689 id=23343 type=MX class=IN name=example.org. size=52 bufsize=1232 opcode=QUERY
```

Which says:

- Zone getting the request: `example.org.`.
- Network: `udp`. Other options are `tcp` or `unix`.
- Remote address and port: `::1 40689`.
- Query ID `23343`.
- Question type, question class, incoming question name: `MX IN example.org.`.
- Size in bytes: `52`.
- Advertised UDP buffer: `1232`.
- Opcode: `QUERY`.

Optionally we can also see:

```txt
2025/10/06 07:25:52 INFO example.org. id.id=5FOXMDAG6YAHD6R7QOZ4UTX7VQ network=udp remote=::1 port=40689 ecs.addr=198.51.100.0 id=23343 type=MX class=IN name=example.org. size=52 bufsize=1232 opcode=QUERY
```

- `ecs.addr=....`, the ecs address if found in the request, via the _ecs_ handler.
- `id.id=....`, the generated request ID, from the _id_ handler.

# Example

Here we add location data to the request's context, _and_ log that.

```conffile
example.org. {
    geoip {
        city testdata/GeoIPCity.dat
    }
    log {
        geoip/city
    }
    whoami
}
```

# Also See

signal(7), atomdns-ecs(7), atomdns-id(7).
