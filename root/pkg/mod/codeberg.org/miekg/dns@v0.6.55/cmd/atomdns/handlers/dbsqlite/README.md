# Name

_dbsqilte_ - serve zone data from a SQLite database

# Description

The _dbsqlite_ handler reads zone data from a data and serves that to clients. If the database contains
signatures (i.e. is signed using DNSSEC), correct DNSSEC answers are returned. Only NSEC is supported. You can
create the database completely off-line, if it holds the correct data, _dbsqlite_ will happily serve from it.

The _sign_ handler does _not_ support databases, so you need something like ldns-signzone to sign and resign
your zones and put the generated records in the database.

When started the database file will be created and the schema will be written to it (if it does not already
exist). After this step, the handler will never write to the database, for the purpose of generating answers
the database is completely read-only. The database can be prepared beforehand.

An RR that fails to be converted into a proper `dns.RR` is silently discarded, unless `debug` is active, see
atomdns-global(7) for details. The class is `IN` and can't be overridden.

When atomdns startup the _dbsqlite_ handler will log how many zones it found in the database, this is a live
query and may differ with the zones specified in the configuration.

The server will reply with minimal responses by default.

## Database

The schema used for the database is:

```sql
CREATE TABLE rrs (
name VARCHAR(255),
type VARCHAR(10),
data VARCHAR(65535),
ttl INTEGER,
UNIQUE (name, type, data)
);
```

You can just add RRs to this table for _any_ zone and _dbsqlite_ will happily use them. Relative names will be
made not be made into fully qualified ones, and for some queries that will not be matched and silently _not_ included.

    sqlite> insert into rrs values ( '_ssh._tcp.host1.example.', 'srv', '10 5 43 example', 3600);
    sqlite> insert into rrs values ( 'subdel.example', 'ns', 'ns.example.com', 3600);

This one database can be safely used for all zones you have. Note that you still have to make sure the handler
gets queries for new zones.

### Importing zone files

If you have a zone file you can use the `.import` feature of SQLite to import the file in one go using the
excellent "ldns" utils from NLnet Labs (https://www.nlnetlabs.nl/projects/ldns/about/).

    ldns-read-zone db.example.org  | sed 's/;.*$//' | sed 's/ $//'  | \
    awk '{print $1 "," $4 "," substr($0, index($0, $5)) "," $2}' > csv.example.org

And then:

    sqlite3 /tmp/db <<EOF
    heredoc> .mode csv
    heredoc> BEGIN;
    heredoc> .import csv.example.org rrs
    heredoc> COMMIT;
    heredoc> EOF

Where the `ldns-read-zone` pipeline removes trailing white space, and the helpful comments after DNSKEY
records, then `awk` re-arranges it into the proper format.

# Syntax

In it simplest form _dbsqlite_ you can use:

```
dbsqlite DATABASE
```

- **DATABASE** the file the sqlite database to query. If the path is relative, the path from the global root config will be
  prepended to it.

If **DATABASE** does not exists the file is created and the `rrs` table is initialized.

For extra control you can open the block and define multiple extra properties that deal with zone transfers. Only outgoing zone
transfers are supported.
It is similar to _dbfile_, and we refer to that documentation then to repeat it here.

```
dbsqlite DATABASE {
    transfer {
        to [IP[:PORT]]... {
            notify IP[:PORT] [IP[:PORT]]...
            source IP [IP]...
            key NAME ALGORITHM SECRET
        }
    }
}
```

# Examples

Have both `example.org` and `example.net` read from the same database.

```conffile
example.org example.net {
    dbsqlite example.db
}
```

If you want _everything_ to end up in _dbsqlite_, you might be tempted to:

```conffile
. {
    dbsqlite root.db
}
```

But this fails, _unless_ you are actually authoritative for `.` (the root zone), this because the zones are
used to find those in the database.
