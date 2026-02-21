# Name

_id_ - add request ID to the context

# Description

_id_ adds a random request ID to the context. Other handlers such as _log_ use it in the logging if present.

# Syntax

```txt
id
```

# Examples

```conffile
example.org {
    id
    any
    whoami
}
```

# Context

The _id_ handler adds a single key to the context:

| Key     | Type     | Example                    | Description |
| :------ | :------- | :------------------------- | :---------- |
| `id/id` | `string` | 5FOXMDAG6YAHD6R7QOZ4UTX7VQ | The ID.     |

When the _log_ handler is used the ID is automatically logged as `id.id=..`.
