# Name

_drunk_ - test client behavior

# Description

_drunk_ sits in between a handler that answers a query and the client, any response can be delayed, dropped or truncated.

# Syntax

```txt
drunk {
    drop [/N]
    truncate [/M]
    delay [/L [DURATION]]
}
```

- `drop`: drop every /**N** query, the default is one in four (/4).
- `truncate`: truncate every /**M** query, the default is /4.
- `delay`: delay every /**L** query for **DURATION**, the default for is /2 and the default for **DURATION** is 100ms.

# Examples

Drop every 1 in 3 queries to `example.org`:

```conffile
example.org {
    drunk {
        drop /3
    }
    whoami
}
```

Or even shorter if the defaults suit you. Note this only drops queries, it does not delay them.

```conffile
example.org {
    drunk
    whoami
}
```

Delay 1 in 3 queries for 50ms

```conffile
example.org {
    drunk {
        delay /3 50ms
    }
    whoami
}
```

Delay 1 in 3 and truncate 1 in 5.

```conffile
example.org {
    drunk {
        delay /3 5ms
        truncate /5
    }
    whoami
}
```
