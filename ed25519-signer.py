#!/usr/bin/env python3
import os,argparse, sys, binascii
from eddsa2 import Ed25519
from keytag3 import calc_keyid

def main():
    parser=argparse.ArgumentParser(description='Ed25519 signing')
    parser.add_argument('-s','--secret',dest='secret', help='secret key file')
    parser.add_argument('-m','--message',dest='tbs', help='to-be-signed data')
    parser.add_argument('-r','--relating',dest='relating', help='relating domain')
    parser.add_argument('-d','--related',dest='related', help='related domain')
    parser.add_argument('-o','--outfile',dest='outfile', help='output file for signature')
    parser.add_argument('-t','--tag',dest='tag', help='tag value to use')
    args=parser.parse_args()

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

if __name__ == "__main__":
    main()

