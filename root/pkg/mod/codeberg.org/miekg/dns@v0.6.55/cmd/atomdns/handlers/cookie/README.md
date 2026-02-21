# Name

_cookie_ - adds an DNS cookie of this server to each reply

# Description

This handler implements the DNS cookie RFC.

# Syntax

```txt
cookie SECRET
```

Where **SECRET** is the secret to use in the server cookie generation record.

# Examples

Enable cookies:

```conffile
example.org {
    cookie Use the force
    whoami
}
```

# Context

The _cookie_ handler adds two keys to the context:

| Key              | Type   | Example | Description                                   |
| :--------------- | :----- | :------ | :-------------------------------------------- |
| `cookie/status`  | `bool` | true    | The validation status of the cookie.          |
| `cookie/msgfunc` | `func` |         | Function that adds reply cookie to the reply. |

# Bugs

_cookie_ does not implement a cache to validate client, is just does enough to make `dig` happy, this implies
that `cookie/status` is always set to true.
