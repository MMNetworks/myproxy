# Handlers

## Query Processing

Once atomdns has been started and has parsed the configuration, it runs a server with handlers chains.
Each handler chain is tied to a set of zones it serves.

When a query is being processed by atomdns, the following steps are performed:

- It will check which one has the most specific zone for this query (longest suffix match). E.g. if there are
  two handler chains, one for example.org and one for a.example.org, and the query is for www.a.example.org, it
  will be routed to the latter.

- Once a handler chains has been found, it will be routed through that chain. This happens in the order as
  defined in the configuration file (atomdns-conffile(5)).

- Each handler in the chain will inspect the query and determine if it should process it. A couple of things
  can now happen:
  1. The query is processed by this handler..
  2. The query is not processed by this handler.
  3. The query is processed by this handler, but it decides it needs to call the next handler.
  4. The query is processed by this handler, a key/value (see [dnsctx])is added to the context and the next
     handler is called.

Processing a query means a handler will respond to the client with a reply.

Note that a handler is free to deviate from the above list as it wishes. Currently, all handlers that come
with atomdns fall into one of these four groups though.

## Logging

Each handler has a generated `zerr.go` file that defines a log function. This function should be used when
logging from within the handler, this uses the standard library `log/slog` package:

```go
alog := log().With(slog.String("path", filepath.Base(d.Path)))
alog.Error("Failed to reload", Err(err))
// or
alog.Info("Successful reload")
```

## Adding a New Handler

There are some minimum requirements before a handler can be added to the main source tree.
It basically boils down to: "it should add something unique and useful to atomdns". Furthermore documentation,
tests and functionality should all be excellent.

It is easier to list when a handler can be included in atomdns than to say it should stay external, so:

- First, the handler should be useful for other people. "Useful" is a subjective term, but the handler needs to
  fill a niche that appeals to more than one person.
- It should be sufficiently different from other handlers.
- Current internet standards need be supported: IPv4 and IPv6 are minimally required.
- It must have tests.
- It must have a README.md for documentation.
- Care must be taken to make it efficient in both memory and CPU.
