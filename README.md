# rdbd-deebeedeerrr

Initial proof-of-concept implementation for
[draft-brotman-rdbd](https://tools.ietf.org/html/draft-brotman-rdbd).  As
always with POC code: DON'T USE THIS - IT'S JUST DEMO CODE!

RDBD is a draft trying to provide a way to assert or disavow relationships
between domains in the DNS. (RDBD == Related Domains By DNS.)

This code generates the zonefile fragments needed to make a basic set of
assertions, including signing those, if desired. 

There is a wrapper for ``dig`` to make looking at those a bit easier. The
wrapper attempts to verify signatures when those are present, which seems to
work ok. 

The code here is used to generate the
[examples](https://github.com/abrotman/related-domains-by-dns/master/mk-examples.sh)
in the RDBD Internet-draft. The core Curve25519 python code is extracted from
[RFC8032](https://tools.ietf.org/html/rfc8032).

The [my-setup.sh](./my-setup.sh) bash script is specific to the set of domains
for which I want to publish RDBD reords. That calls
[make-zonefrags.sh](./make-zonefrags.sh) which generates the fragments one
would need to put in a (set of) zone file(s) to publish a (set of)
relationship(s). That in turn uses OpenSSL for RSA operations and python code
for Ed25519 and DNS wire format encoding.

The zone fragments produced seem to be syntactically correct enough to publish
and query at least.

In order to try see how RDBD support might usefully be added to tooling like
``dig``, I've made a wrapper script [dig-wrapper.sh](./dig-wrapper.sh) that's
fairly basic, so is likely to break if you supply complicated dig command line
arguments, but it does decode the ASCII hex that you'd otherwise see with dig
and verify signatures if those are present. 

            $ ./dig-wrapper.sh RDBD tolerantnetworks.ie
            
            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> RDBD tolerantnetworks.ie
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28169
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ; COOKIE: d3e26ca48862380086f4d4535d8252310dfd862ccb81379f (good)
            ;; QUESTION SECTION:
            ;tolerantnetworks.ie. IN RDBD
            
            ;; ANSWER SECTION:
            tolerantnetworks.ie.   2252   IN   RDBD RELATED https://tolerantnetworks.com/rdbdeze.json
            tolerantnetworks.ie.   2252   IN   RDBD RELATED my-own.net
            tolerantnetworks.ie.   2252   IN   RDBD RELATED my-own.ie
            tolerantnetworks.ie.   2252   IN   RDBD UNRELATED my-own.com
            tolerantnetworks.ie.   2252   IN   RDBD RELATED tolerantnetworks.com Sig: good KeyId: 50885 Alg: 8 Sig: i04agbJqhhEGE6x+6G1QeGe+Ji/gFeVNrfmNnbPg2w1wPv17jnzJ9g1mdTYk2em7obcuayMornBZbq0RslBDR2cHloJh/Uejekhji7M7oQTxwi0grO7VXfW+tkbpN1jAl6uCW0uq0C7OT5JxA7t1e8SdRetvriJhGbO2oXo3vRmgAWeOISZzJpEt3hlvN8uSbPRHB/C0c5yfHH++FGvJmAjFgJniN/tTnKesTE7s6RkUaVzcW9xgyZpVzSTsk/whUfThvf+oVp5AWoga75DA1nQK7fS9qjsuar409aW1+O32Tu4dMDC5TGXU2og3bQx1RWWp3ilnHZ9sdDbv4oOLpg==
            
            ;; Query time: 152 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Wed Sep 18 16:50:08 IST 2019
            ;; MSG SIZE rcvd: 600
            
            
            $ ./dig-wrapper.sh RDBD tolerantnetworks.com
            
            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> RDBD tolerantnetworks.com
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50000
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ; COOKIE: 4176df14ee8c4c3fbeb045705d825258161587cd1c00b08c (good)
            ;; QUESTION SECTION:
            ;tolerantnetworks.com. IN RDBD
            
            ;; ANSWER SECTION:
            tolerantnetworks.com.   1522   IN   RDBD RELATED tolerantnetworks.ie Sig: good KeyId: 1878 Alg: 15 Sig: T/fkaNax0VaTd0FSt5r6gkNz21aoRFoHJ/LVF6rSJoZCbO1N405veToZuomtmupnHrlyKxh4bnLkkvijUKtlBQ==
            
            ;; Query time: 138 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Wed Sep 18 16:50:48 IST 2019
            ;; MSG SIZE rcvd: 199
            
            
            $ ./dig-wrapper.sh RDBDKEY tolerantnetworks.ie

            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> RDBDKEY tolerantnetworks.ie
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30827
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ;; QUESTION SECTION:
            ;tolerantnetworks.ie. IN RDBDKEY
            
            ;; ANSWER SECTION:
            tolerantnetworks.ie.   3600   IN   RDBDKEY Alg: 15 Public key: b9jYj7ZU9P5cc4QKm0LYnjwikNf4N0pHYOGKFKVxHEs=
            
            ;; Query time: 437 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Thu Aug 29 15:47:06 IST 2019
            ;; MSG SIZE rcvd: 115
            

Of course you can also still use ``dig`` to see the
raw values from the DNS.

            $ dig TYPE65443 tolerantnetworks.ie
            
            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> TYPE65443 tolerantnetworks.ie
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33907
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ;; QUESTION SECTION:
            ;tolerantnetworks.ie.		IN	TYPE65443
            
            ;; ANSWER SECTION:
            tolerantnetworks.ie.	2123	IN	TYPE65443 \# 14 0000066D792D6F776E03636F6D00
            tolerantnetworks.ie.	2123	IN	TYPE65443 \# 283 000110746F6C6572616E746E6574776F726B7303636F6D00C6C5088B 4E1A81B26A86110613AC7EE86D507867BE262FE015E54DADF98D9DB3 E0DB0D703EFD7B8E7CC9F60D66753624D9E9BBA1B72E6B2328AE7059 6EAD11B25043476707968261FD47A37A48638BB33BA104F1C22D20AC EED55DF5BEB646E93758C097AB825B4BAAD02ECE4F927103BB757BC4 9D45EB6FAE226119B3B6A17A37BD19A001678E21267326912DDE196F 37CB926CF44707F0B4739C9F1C7FBE146BC99808C58099E237FB539C A7AC4C4EECE91914695CDC5BDC60C99A55CD24EC93FC2151F4E1BDFF A8569E405A881AEF90C0D6740AEDF4BDAA3B2E6ABE34F5A5B5F8EDF6 4EEE1D3030B94C65D4DA88376D0C754565A9DE29671D9F6C7436EFE2 838BA6
            tolerantnetworks.ie.	2123	IN	TYPE65443 \# 45 00012968747470733A2F2F746F6C6572616E746E6574776F726B732E 636F6D2F72646264657A652E6A736F6E00
            
            ;; Query time: 311 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Thu Aug 29 14:12:36 IST 2019
            ;; MSG SIZE  rcvd: 483
            
            
            $ dig TYPE65448 tolerantnetworks.ie
            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> TYPE65448 tolerantnetworks.ie
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28911
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ; COOKIE: 1ec5ef76adb6f8bf0fd6de5e5d67cf791c5d7bb64c20ac3a (good)
            ;; QUESTION SECTION:
            ;tolerantnetworks.ie.		IN	TYPE65448
            
            ;; ANSWER SECTION:
            tolerantnetworks.ie.	3600	IN	TYPE65448 \# 36 0000030F6FD8D88FB654F4FE5C73840A9B42D89E3C2290D7F8374A47 60E18A14A5711C4B
            
            ;; Query time: 48 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Thu Aug 29 14:13:29 IST 2019
            ;; MSG SIZE  rcvd: 143

To help convince us all that the signature checking is real, 
you can break the signatures before they are checked to see
the "bad" output. To do that set the ``SIGBREAK`` environment
variable to "yes" before running the wrapper, e.g.:

            $ SIGBREAK=yes ./dig-wrapper.sh RDBD tolerantnetworks.com
            BREAKING SIGNATURES as requested!!
            
            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> RDBD tolerantnetworks.com
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15246
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ; COOKIE: 5d7c47e31ba67e9babe447745d8252b5dbc3da38cdefe1b4 (good)
            ;; QUESTION SECTION:
            ;tolerantnetworks.com. IN RDBD
            
            ;; ANSWER SECTION:
            tolerantnetworks.com.   1429   IN   RDBD RELATED tolerantnetworks.ie Sig: bad KeyId: 1878 Alg: 15 Sig: T/fkaNax0VaTd0FSt5r6gkNz21aoRFoHJ/LVF6rSJoZCbO1N405veToZuomtmupnHrlyKxh4bnLkkvijUKtlBQ==
            
            ;; Query time: 137 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Wed Sep 18 16:52:20 IST 2019
            ;; MSG SIZE rcvd: 199
            



