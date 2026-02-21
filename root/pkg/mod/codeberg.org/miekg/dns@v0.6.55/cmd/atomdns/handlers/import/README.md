# Name

_import_ - includes files or references snippets from a Conffile

# Description

The _import_ handler can be used to include files into the main configuration. Another use is to
reference predefined snippets. Both can help to avoid some duplication.

This is a unique handler in that _import_ can appear outside of a handler block. In other words, it
can appear at the top of a Conffile where an address would normally be.

You can have a maximum of 1000 imports in the configuration, this is to prevent cycles.

# Syntax

```
import PATTERN
```

- **PATTERN** is the file, glob pattern (`*`) or snippet to include. Its contents will replace
  this line, as if that file's contents appeared here to begin with.

# Files

You can use _import_ to include a file or files. This file's location is relative to the
Conffile's location. It is an error if a specific file cannot be found, but an empty glob pattern is
not an error.

# Snippets

You can define snippets to be reused later in your Conffile by defining a block with a single-token
label surrounded by parentheses:

```conffile
(mysnippet) {
	...
}
```

Then you can invoke the snippet with _import_:

```
import mysnippet
```

# Examples

Import a shared configuration:

```
. {
   import config/common.conf
}
```

Where `config/common.conf` contains:

```
prometheus
errors
log
```

This imports files found in the zones directory:

```
import ../zones/*
```

# See Also

See atomdns-conffile(5).
