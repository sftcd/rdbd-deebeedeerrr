#!/usr/bin/env python3

# Do Ed25519 signing or verification - see the bottom for
# arguments.

# If doing signature verification then the result returned
# to the shell will be 0 for success or 2 for a signature
# failure. A value of 1 means that something was wrong
# with the inputs (e.g. a file not found or argument not
# supplied)

import os,argparse, sys, binascii
from eddsa2 import Ed25519
from keytag3 import calc_keyid

def sign():

    if args.secret is None:
        print("You do need a secret... - exiting")
        sys.exit(1)

    with open(args.secret,"rb") as f:
        secret=f.read()
    privkey,pubkey = Ed25519.keygen(secret)

    if args.tbs is not None:
        tbs=args.tbs
    else:
        if args.relating is None:
            print("You do need a relating domain... - exiting")
            sys.exit(1)
        if args.related is None:
            print("You do need a related domain... - exiting")
            sys.exit(1)
        rdbdtag="1"
        if args.tag:
            rdbdtag=args.tag

        b64pubkey=binascii.b2a_base64(pubkey).rstrip().decode("utf-8")
        keyid=calc_keyid("0","3","15",b64pubkey)

        tbs="relating="+args.relating+"\nrelated="+args.related+"\nrdbd-tag="+rdbdtag+"\nkey-tag="+str(keyid)+"\nsig-alg=15\n"
        #print("to-be-signed:|" + str(tbs)+"|")

    msg=tbs.encode('utf-8')
    signature = Ed25519.sign(privkey, pubkey, msg)
    if args.outfile is not None:
        with open(args.outfile, "wb") as sigf:
           sigf.write(signature)
    else:
        print(str(binascii.hexlify(signature)))
    return

def verify():
    if args.public is None:
        print("No public key supplied - exiting")
        sys.exit(1)
    if args.tbs is None:
        print("No message supplied - exiting")
        sys.exit(1)
    if args.sig is None:
        print("No signature supplied - exiting")
        sys.exit(1)
    # check public is file name or base64 that decodes to 32 octets
    if os.path.exists(args.public):
        with open(args.public,"rb") as f:
            public=f.read()
    else:
        public=binascii.a2b_base64(args.public)
    message=args.tbs.encode('utf-8')
    # try ascii-hex first, then base64 decode...
    try:
        signature=binascii.unhexlify(args.sig)
    except:
        signature=binascii.a2b_base64(args.sig)

    result = Ed25519.verify(public, message, signature)
    '''
    if result is True:
        print("Signature verified")
        return 
    else:
        print("Signature check failed")
    '''
    return result

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description='Ed25519 signing/verification')
    parser.add_argument('-p','--public',dest='public', help='public key file, or base64 encoded value')
    parser.add_argument('-S','--signature',dest='sig', help='signature to verify')
    parser.add_argument('-s','--secret',dest='secret', help='secret key file')
    parser.add_argument('-m','--message',dest='tbs', help='to-be-signed data')
    parser.add_argument('-r','--relating',dest='relating', help='relating domain')
    parser.add_argument('-d','--related',dest='related', help='related domain')
    parser.add_argument('-o','--outfile',dest='outfile', help='output file for signature')
    parser.add_argument('-t','--tag',dest='tag', help='tag value to use')
    args=parser.parse_args()

    if args.secret is not None:
        sign()
    elif args.public is not None:
        rv=verify()
        if rv is True:
            sys.exit(0)
        else:
            sys.exit(2)
    else:
        print("Error you must provide a secret (to sign) or public value (to verify)")
        sys.exit(1)


