# Name

_any_ - give a minimal response to ANY queries

# Description

_any_ basically blocks ANY queries by responding to them with a short HINFO reply. See [RFC
8482](https://tools.ietf.org/html/rfc8482) for details.

# Syntax

```txt
any
```

# Examples

```conffile
example.org {
    any
    whoami
}
```

A `dig +nocmd ANY example.org +noall +answer` now returns:

```txt
example.org.  8482	IN	HINFO	"ANY obsoleted" "See RFC 8482"
```

# See Also

[RFC 8482](https://tools.ietf.org/html/rfc8482).
