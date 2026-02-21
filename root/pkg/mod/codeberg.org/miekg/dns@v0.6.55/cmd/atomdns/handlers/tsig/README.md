# Name

_tsig_ - validate incoming TSIG signed messages

# Description

With _tsig_, you can define TSIG secret keys. Using those keys, _tsig_ validates incoming TSIG messages. This
is only done for notifies and zone transfers. It does not itself sign messages; it is up to the respective
handler sending those to use the data added to the context by _tsig_. See the "Context" section for details.

# Syntax

```
tsig NAME ALGORITHM SECRET
```

- **SECRET** must be base64 encoded. **NAME** is the name of the key (this is a domain name, and may thus
  contain dots). And **ALGORITHM** is the key's algorithm like `hmac-sha512` for instance. See the `Hmac*`
  constants in the dns package.

# Examples

```
example.org {
  tsig example.org.key hmac-sha512 NoTCJU+DMqFWywaPyxSijrDEA/eC3nK0xi3AMEZuPVk=
  dbhost ... {
    # ...
  }
}
```

# Context

The _tsig_ handler adds the following keys to the context:

| Key              | Type     | Example          | Description                    |
| :--------------- | :------- | :--------------- | :----------------------------- |
| `tsig/status`    | `bool`   | true             | The validation status of TSIG. |
| `tsig/name`      | `string` | example.org.key. | Name, as configured.           |
| `tsig/secret`    | `string` | No...Pkv=        | Secret, as configured.         |
| `tsig/algorithm` | `string` | hmac-sha512.     | Algorithm, as configured.      |

Each of these can be used by respective "upstream" handlers to sign messages. Note _tsig_ does not register a
`tsig/msgfunc` as these are unconditionally executed by all handlers that returns a message.
