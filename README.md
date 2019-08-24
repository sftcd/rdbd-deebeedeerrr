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

The [my-seutp.sh](./my-setup.sh) bash script calls [make-zonefrags.sh](./make-zonefrags.sh)
which generates the fragments one would need to put in a (set of) zone file(s) to
publish a (set of) relationship(s). 


