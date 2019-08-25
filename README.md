# rdbd-deebeedeerrr

Initial proof-of-concept implementation for [draft-brotman-rdbd](https://tools.ietf.org/html/draft-brotman-rdbd).
As always with POC code: DON'T USE THIS - IT'S JUST DEMO CODE!

RDBD is a draft trying to provide a way to assert or disavow relationships 
between domains in the DNS. (RDBD == Related Domains By DNS.)

To start with, this code just handles generating the zonefile fragments 
needed to make a basic set of assertions.

Some of the python code here is inherited from the code to generate the
[samples](https://github.com/abrotman/related-domains-by-dns/master/sample)
in the RDBD Internet-draft. The core Curve25519 python code is just extracted from
[RFC8032](https://tools.ietf.org/html/rfc8032).

The [my-seutp.sh](./my-setup.sh) bash script is specific to the 
set of domains for which I want to publish RDBD reords. That 
calls [make-zonefrags.sh](./make-zonefrags.sh)
which generates the fragments one would need to put in a (set of) zone file(s) to
publish a (set of) relationship(s). That in turn uses OpenSSL for
RSA operations and python code for Ed25519 and DNS wire format
encoding.

The zone fragments produced seem to be syntactically correct enough
to publish and query at least.

            $ dig TYPE65443 tolerantnetworks.ie
            
            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> TYPE65443 tolerantnetworks.ie
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45740
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ; COOKIE: 84299598be6e195347e626055d62aa8d620b8ba3e257d836 (good)
            ;; QUESTION SECTION:
            ;tolerantnetworks.ie.		IN	TYPE65443
            
            ;; ANSWER SECTION:
            tolerantnetworks.ie.	3	IN	TYPE65443 \# 25 000110746F6C6572616E746E6574776F726B7303636F6D0000
            
            ;; Query time: 805 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Sun Aug 25 16:34:37 IST 2019
            ;; MSG SIZE  rcvd: 132

            $ dig TYPE65448 tolerantnetworks.ie
            
            ; <<>> DiG 9.11.5-P1-1ubuntu2.5-Ubuntu <<>> TYPE65448 tolerantnetworks.ie
            ;; global options: +cmd
            ;; Got answer:
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 56807
            ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
            
            ;; OPT PSEUDOSECTION:
            ; EDNS: version: 0, flags:; udp: 4096
            ; COOKIE: 7119d71b56ce328f1ee61b465d62aab31e172d449b6fec9f (good)
            ;; QUESTION SECTION:
            ;tolerantnetworks.ie.		IN	TYPE65448
            
            ;; ANSWER SECTION:
            tolerantnetworks.ie.	3600	IN	TYPE65448 \# 298 
                0000030830820122300D06092A864886F70D01010105000382010F00 
                3082010A028201010095B058C997072DD1FBB4F6FFA47CDD56CA5C44 
                B5B049150457544EE9061525AD6041B32ED63268B665256EF5B36BF9 
                0C207028BE77641803D5BE4CE15EB7B65D4CA48993AD31674294191F 
                290B96113E1144FACAEF792FF0EE92EEAAF145D7F882F10F506CADF1 
                A216B9FDA2F6ADD0EF955B0B1C95C3D455DFA444405477E398C79023 
                2E848E2A3B85F30A6E2F9C1475014038394A3975C5B70E7638DEF9DE 
                0E4FB7E9FC9AC9F7DF6D284F7AF03D975FDE4076D202C1C032131851 
                4316C78E20805EE8196195CECFC7EB526273053E6D5451A7BFEF2475 
                A408EC95FFB023BF4842386995F04E3C30E75BD32D92F12C169050CE 
                081FA7DA31102DF98C8E5113CD0203010001
            
            ;; Query time: 185 msec
            ;; SERVER: 127.0.0.1#53(127.0.0.1)
            ;; WHEN: Sun Aug 25 16:35:15 IST 2019
            ;; MSG SIZE  rcvd: 405



