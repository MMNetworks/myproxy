# Name

_chaos_ - respond to TXT queries in the CH class

# Description

This is useful for retrieving version or author information from the server by querying a TXT record
for a special domain name in the CH class.

# Syntax

```
chaos [VERSION] {
    authors {
        "First Author"
        "Second Author"
        ...
    }
}
```

- **VERSION** is the version to return. Defaults to "Served by atomdns, https://atomdns.miek.nl" if not set.
- The `authors` section holds the authors that are returned.

Note that you have to make sure that this handler will get actual queries for
the following zone _prefixes_: `version.`, `authors.`, `hostname.` and `id.`,
i.e. having `version.example.org` will suffice to get queries for the
`version.` prefix.

# Examples

Specify all the zones:

```conffile
version.bind version.server authors.bind hostname.bind id.server authors.server {
    chaos atomdns-001 {
        authors {
            info@example.org
        }
    }
}
```

And test with `dig`:

```txt
% dig @localhost CH TXT version.bind

;; ANSWER SECTION:
version.bind.		0	CH	TXT	"atomdns-001"
```
