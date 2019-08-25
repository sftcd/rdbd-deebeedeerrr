#!/usr/bin/env python3

import os,argparse, sys, binascii

# encode binary format RR values for inclusion in zone files

# output here is of the possibly multi-line text zone fragment 
# to include in the zone file, the last element of that will
# be the binary encoding of the DNS answer - as that's binary
# we'll encode via python 

def encode_rdbd(preamble, args):
    ''' 
    format is:
                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           rdbd-tag            |                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
    /                 Related-domain name or URL                    /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+--+-+|
    |    key-tag                    | sig-alg     |                 /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                 /
    /                            signature                          /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    # check we have the right args 
    if args.tag is None:
        print("No RDBD tag supplied - exiting")
        return(21)
    if args.related is None:
        print("No related name supplied - exiting")
        return(22)
    # remaining fields are optional, but if we get one, we need 'em all
    dosig=False
    if (args.keytag is not None or args.sigalg is not None or args.sig is not None):
        if (args.keytag is None or args.sigalg is None or args.sig is None):
            print("Missing signature fields - exiting")
            return(23)
        dosig=True
    # check if related name is DNS name or https URL
    URL=False
    if args.related.startswith("https://"):
        URL=True
    if args.tag > 65535 or args.tag < 0:
        print("Bad value for RDBD tag ("+str(args.tag)+") - exiting")
        return(24)
    if dosig is True:
        if args.keytag > 65535 or args.keytag < 0:
            print("Bad value for RDBD keytag ("+str(args.keytag)+") - exiting")
            return(24)
        if args.sigalg > 255 or args.sigalg < 0:
            print("Bad value for sigalg ("+str(args.sigalg)+") - exiting")
            return(24)
    encoded=bytearray()
    # encode tag
    encoded.append(args.tag>>8);
    encoded.append(args.tag%256);
    # encode name or URL
    if URL is True:
        encoded += args.related.encode('utf-8')
    else:
        # ok we'll try encode into DNS wire format, probably badly;-(
        name_enc=bytearray()
        arr=args.related.split('.')
        for label in arr:
            # I bet this shouldn't be called ulabel:-)
            ulabel=label.encode('utf-8')
            if len(ulabel) > 63:
                print("Bummer: label too long - exiting")
                sys.exit(63)
            name_enc.append(len(ulabel)%256)
            name_enc+=ulabel
        encoded+=name_enc
        encoded.append(0)
    if dosig is True:
        # add signature shite
        encoded.append(args.keytag>>8);
        encoded.append(args.keytag%256);
        encoded.append(args.sigalg)
        rawsig=binascii.a2b_base64(args.sig)
        encoded+=rawsig

    return encoded

def encode_rdbdkey(preamble, args):
    return 0

def encodem():
    parser=argparse.ArgumentParser(description='RDBD RR encoding')
    parser.add_argument('-o','--owner',dest='owner', help='owner name for entry')
    parser.add_argument('-t','--ttl',dest='ttl', help='ttl value to use')
    parser.add_argument('-T','--type',dest='type', help='type code to use')
    parser.add_argument('-g','--tag',dest='tag', type=int, help='RDBD tag value to use')
    parser.add_argument('-r','--related',dest='related', help='related name value to use')
    parser.add_argument('-a','--sigalg',dest='sigalg', type=int, help='sigalg value to use')
    parser.add_argument('-k','--keytag',dest='keytag', type=int, help='(optional) RDBDKEY keytag value to use')
    parser.add_argument('-s','--sig',dest='sig', help='(optional) signature value')
    parser.add_argument('-p','--public',dest='public', help='public key value')
    args=parser.parse_args()

    # check generic args
    if args.type is None:
        print("Error - no RR type given - exiting")
        sys.exit(1)
    if args.owner is None:
        print("Error - no owner name given - exiting")
        sys.exit(2)
    if args.ttl is None:
        print("Error - no ttl given - exiting")
        sys.exit(3)
    preamble=args.owner+"\t\tIN "+args.ttl+" "+args.type+" "
    if args.type.upper() == "TYPE65443" or args.type.upper() == "RDBD": 
        encoded=encode_rdbd(preamble,args)
    if args.type.upper() == "TYPE65448" or args.type.upper() == "RDBDKEY":
        encoded=encode_rdbdkey(apreamble,rgs)
    elen=len(encoded)
    ah=encoded.hex()
    wspace='             '
    lfa="".join(ah[i:i+45] + "\n"+wspace for i in range(0,len(ah),45))
    print(preamble+"\#"+str(elen)+" (\n"+wspace+lfa+")")
    return

if __name__ == "__main__":
    encodem()
