# Name

_sign_ - add DNSSEC records to zone files

# Description

The _sign_ "handler" is used to sign zones. In this process DNSSEC resource records are
added. The signatures that sign the resource records sets have an expiration date, this means the
signing process must be repeated before this expiration data is reached. Otherwise the zone's data
will go BAD (RFC 4035, Section 5.5). The _sign_ handler takes care of this.

_sign_ can work in conjunction with the _dbfile_ handler; this handler **signs** the zone's files, and
_dbfile_ **serves** the zone's _data_.

For this handler to work at least one key is needed. This "Common Signing Key" will be used to sign the entire
zone, _sign_ does _not_ support the ZSK/KSK split, nor will it do key or algorithm rollovers - it just signs.
This is the most authentic way of doing DNSSEC as it mimics the fire-and-forget style of the DNS.

By default every record will get a TTL of 3600 seconds, but see the `ttl` option.

_sign_ will:

- (Re)-sign the zone with the CSK(s) when:
  - The first signature found on the SOA only has 9 days left before expiring.
  - The source zone file has been written to.

When signing it will:

- Add the DNSKEYs to the apex of the zone.

- Create RRSIGs that have an inception of -3 hours (minus a jitter between 0 and 18 hours)
  and a expiration of +32 (plus a jitter beteen 0 and 100 hours) days for every given DNSKEY.

- Add NSEC records for all authoritative names in the zone.

- Add or replace _all_ apex CDS/CDNSKEY records with the ones derived from the given keys. For
  each key two CDS are created one with SHA1 and another with SHA256.

- Update the SOA's serial number to the _unix epoch_ of when the signing happens. This will
  overwrite _any_ previous serial number.

The state of each (signed) zone will be checked at 5 hour intervals.

Keys are named (following BIND9): `K<name>+<alg>+<id>.key` and `K<name>+<alg>+<id>.private`.
The keys **must not** be included in your zone; they will be added by _sign_. These keys can be
generated with `ldns-keygen` or BIND9's `dnssec-keygen`. You don't have to adhere to this naming
scheme, but then you need to name your keys explicitly, see the `keys` directive, and note that
`.key` and `.private` is always used as a suffix.

A generated zone is written out in a file named `<name>.signed` in the directory named by the
`directory` directive or otherwise the directory where to original file is found.

# Syntax

```
sign FILE {
    ttl TTL
    key KEYFILE [KEYFILE]...
    directory DIRECTORY
    zonemd
}
```

- **FILE** is the input zone file to sign. If the path is relative, the path from the _root_ global handler will be prepended to it.
- `ttl` specifies the TTL of all records that will be signed, and for the new records (NSEC, RRSIG) that get added to the zone. Without
  this option all records that are signed will get a TTL of 3600.
- `key` specifies the key(s) (there can be multiple) to sign the zone. Any metadata in these files (Activate, Publish, etc.) is
  _ignored_. These keys must also be Key Signing Keys (KSK). The **KEYFILE** must be the root name of the keys
  files, i.e if you have "Kmiek.nl.+013+26205.key", **KEYFILE** must be "Kmiek.nl.+013+26205". For finding the
  keys files the same rules apply as for **FILE**.
- **DIRECTORY** specifies where to write the signed zone files. If not specified the directory where **FILE**
  is found is used. If the path is relative, the global _root_ will be prepended.
- if `zonemd` is specified the zone will be signed and a ZONEMD record will be added afterwards. This requires
  the entire zone to be sorted and be converted into wire-format.

# Examples

Sign the `example.org` zone contained in the file `db.example.org` and write the result to
`db.example.org.signed` to let the _dbfile_ handler pick it up and serve it. The keys used
are read from `Kexample.org.+013+32412.key` and `Kexample.org.+013+32412.private`.

```txt
example.org {
    sign db.example.org {
        key Kexample.org.+013+32412
    }
    dbfile db.example.org.signed
}
```

Running this leads to the following log output

```txt
2025/09/15 12:00:35 INFO example.org. handlers=log,sign,dbfile
2025/09/15 12:00:35 INFO Start: /metrics handler=global
2025/09/15 12:00:35 INFO Startup: signing: db.example.org handler=sign
2025/09/15 12:00:35 INFO Zone "example.org." in "db.example.org" is signed and is written to db.example.org.signed handler=sign
2025/09/15 12:00:35 INFO Startup: reload: db.example.org.signed handler=dbfile
2025/09/15 12:00:47 INFO Zone "example.org." in "db.example.org" is signed and is written to db.example.org.signed handler=sign
2025/09/15 12:00:47 INFO Resign of zone "example.org." in "db.example.org" successful handler=sign
2025/09/15 12:00:49 INFO Reload of zone "example.org." in "db.example.org.signed" successful handler=dbfile
```

Forcibly resigning a zone can be accomplished by removing the signed zone file (atomdns will keep
on serving it from memory), and `touch`-ing **FILE**.

# Metrics

If monitoring is enabled the following metrics are exported:

- `atomdns_sign_duration_seconds{zone}` - tracks how long each signing operation takes.
- `atomdns_sign_rrsig_expire_timestamp{zone}` - shows when the signatures are about to expire.

# See Also

The DNSSEC RFCs: RFC 4033, RFC 4034 and RFC 4035. And the best current practice (BCP) on DNSSEC, RFC 6781. And
the _dbfile_ handler's documentation. Useful DNS(SEC) tools can be found in
[ldns](https://nlnetlabs.nl/projects/ldns/about/), e.g. `ldns-key2ds` to create DS records from DNSKEYs.
