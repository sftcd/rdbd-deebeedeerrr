#!/usr/bin/env python3

import os,argparse, sys, binascii
from eddsa2 import Ed25519
from keytag3 import calc_keyid

def main():
    parser=argparse.ArgumentParser(description='Generate Ed25519 key pair from secret key')
    parser.add_argument('-s','--secret',dest='secret', help='secret key (input)')
    parser.add_argument('-p','--public',dest='public', help='public key file (output)')
    args=parser.parse_args()

    if args.secret is None:
        print("You do need a secret... - exiting")
        sys.exit(1)
    if args.public is None:
        print("You do need a public key file nae... - exiting")
        sys.exit(2)
    secval=args.secret
    # but... secret can also be a file name, if so, we'll try read that
    if os.path.isfile(args.secret) and os.access(args.secret,os.R_OK) and os.path.getsize(args.secret)==32:
        f=open(args.secret,'rb')
        secret=f.read()
        f.close()
    else:
        secret=secval.encode('utf-8')
    # secret has to be 32 octets funnily enuugh:-)
    # e.g. secret="rdbd-example0001rdbd-example0002".encode('utf-8')
    if len(secval)!=32:
        print("Secret has to be 32 octets...(it's " + str(len(secval)) + " - exiting")
        sys.exit(1)
    privkey,pubkey = Ed25519.keygen(secret)
    with open(args.public,"wb") as pubf:
        pubf.write(pubkey)
    return

if __name__ == "__main__":
    main()

