# Name

_kill_ - stop the server after a duration

# Description

_kill_ stops the server after some amount of time. Its main use is to spin up a server, perform a minimal
check and be certain it will shut itself down again. This minimizes the CI/CD setup that is needed, as you can
just start atomdns in the background and forget about it.

As this takes down the entire server it doesn't matter in which handler block it is specified.

# Syntax

```txt
kill DURATION
```

# Examples

```conffile
example.org {
    kill 10s
    any
    whoami
}
```

# Bugs

The server's shutdown handlers are not executed.
