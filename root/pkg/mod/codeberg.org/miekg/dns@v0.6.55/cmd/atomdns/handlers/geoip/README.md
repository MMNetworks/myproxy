# Name

_geoip_ - add geographical location data

# Description

The _geoip_ handler adds geographical location data associated with the client IP. You can install a database
on Debian systems with `apt-get install geoip-database`, or see https://mailfud.org/geoip-legacy/.

There is no automatic reloading of the databases under the assumption they will not change _that_ often.

If an IP address does not have associated geographical location data, nothing is added to the context. If the
_ecs_ handler is active and has added data to the context the address from there is used instead of the
sources address of the query.

# Syntax

```
geoip {
    city DBFILE4 [DBFILE6]
    asn DBFILE4 [DBFILE6]
}
```

- `city` and `asn` define the database files that should be used for country, city or AS number
  lookups. If the path is relative the path from `root` will be prepended. At least one database must be
  loaded.

# Context

The following values will be stored in the context of a request and can be used by other handlers.

The continent codes are: `AF`: Africa, `AN`: Antarctica, `AS`: Asia, `EU`: Europe, `NA`: North America,
`OC`: Oceania, `SA`: South America.

| Key                      | Type       | Example       | Description                        |
| :----------------------- | :--------- | :------------ | :--------------------------------- |
| `geoip/city`             | `string`   | Cambridge     | The city name in English language. |
| `geoip/city/region`      | `[]string` | ENG TWH       | Regional ISO 3166-2 codes.         |
| `geoip/country`          | `string`   | GB            | Country ISO 3166-1 code.           |
| `geoip/country/eu`       | `bool`     | false         | Country is EU member.              |
| `geoip/continent`        | `string`   | EU            | Continent code.                    |
| `geoip/latitude`         | `float64`  | 52.2242       | Base 10, max available precision.  |
| `geoip/longitude`        | `float64`  | 0.1315        | Base 10, max available precision.  |
| `geoip/timezone`         | `string`   | Europe/London | The time zone.                     |
| `geoip/asn`              | `int`      | 37            | The AS number.                     |
| `geoip/asn/organization` | `string`   | Example Org   | The AS organization.               |

# Example

Here we add location data to the request's context, so that _template_ can use it in the template creation.

```conffile
example.org. {
    geoip {
        city testdata/GeoIPCity.dat
    }

    template .* {
        mytemplate.go.tmpl
    }
}
```

# See Also

See the _ecs_ handler.
