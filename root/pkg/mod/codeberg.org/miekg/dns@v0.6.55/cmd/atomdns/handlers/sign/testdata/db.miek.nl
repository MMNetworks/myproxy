$TTL 30M
$ORIGIN miek.nl.
@                        IN   SOA        linode.atoom.net. miek (
                                            1282630074   ; serial  Fri, 28 Feb 1287 17:16:00 UTC
                                            4H           ; refresh
                                            1H           ; retry
                                            1W           ; expire
                                            4H           ; minimum
                                            )
                         IN   NS         omval.tednet.nl.
                         IN   NS         linode.atoom.net.
                         IN   NS         ns-ext.nlnetlabs.nl.
                         IN   MX         1 aspmx.l.google.com.
                         IN   AAAA       2a01:7e00::f03c:91ff:fe79:234c

a                        IN   AAAA       2a01:7e00::f03c:91ff:fe79:234c

www                      IN   CNAME      a

bla                      IN   NS         ns1.bla.com.

ns3.blaaat               IN   AAAA       ::1

; in baliwick nameserver that requires glue, should not be signed
bla                      IN   NS         ns2.bla

ns2.bla                  IN   A          127.0.0.1

toolong           4W5D   IN   TXT        "overly long TTL, should be truncated"

secure                   IN   NS         ns1.bla.com.
                         IN   DS         33694 8 2 (
                                            2C235500B09FA87BBC0981674FC31AF87D2FA4DCFE666A64BA2646F
                                            29651DB83    
                                            )
