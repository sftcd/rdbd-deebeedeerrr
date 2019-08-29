#!/bin/bash

# set -x

# RDBD and RDBDKEY zonefile fragment producer, see the
# usage function for details.

# The key pair values for Relating-domain "R" is stored in 
# $KEYDIR/sha256(R).priv and $KEYDIR/sha256(R).pub.

# The hashing is so that we don't need to worry about
# i18n for file names, and because I can:-)

# set directories
RDIR="$HOME/code/rdbd-deebeedeerrr"

function usage()
{
    echo "$0 -i relating-domain -d related-domain [-t tag-no ] [-p privkeydir] [-ershv]"
    echo ""
    echo "Create the relevant zonefile fragments matching the ipnputs"
    echo "-h - produce this"
    echo "-v - be verbose"
    echo "-g - generate new key pair"
    echo "-r - use RSA"
    echo "-e - use EdDSA"
    echo "-i - specify the relating domain to use"
    echo "-d - specify the related domain to use"
    echo "-p - specify the private key file directory"
    echo "-t - specify the rdbd-tag value to use (1=avow, 0=disavow, default is 1)"
    echo "-s - make a digital signature for this"
    echo ""
    echo "You can either generate a key pair (RDBDKEY) or create one,"
    echo "posssibly signed, RDBD record."
    echo ""
    echo "To generate a key pair you need to use -g, and specify the"
    echo "Relating-domain. You can specify RSA or Ed25519 (default)."
    echo ""
    echo "To generate an RDBD record, you need to specify both the"
    echo "Relating-domaian (-i) and Related-domain (-d), and the RDBD "
    echo "tag (-t). If you want that signed, use -s, and then the "
    echo "relevant private key needs to exist and match the signing "
    echo "algorithm (-r or -e) which again will default to Ed25519."

    exit 99
}

# Set default values if not already set in the environment
: "${KEYDIR:="."}"
: "${VERBOSE:="no"}"
: "${TAG:="1"}"
: "${SIGN:="no"}"
: "${EDDSA:="yes"}"
: "${RSA:="no"}"
: "${OBIN=`which openssl`}"

# set blank values
RELATING=""
RELATED=""

# don't allow overriding this via environment, not sure why:-)
KEYGEN="no"

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o i:d:p:t:shverg -l relating:,related:,privdir:,tag:,sign,help,verbose,eddsa,rsa,keygen -- "$@")
then
    # something went wrong, getopt will put out an error message for us
    exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
    case "$1" in
        -h|--help) usage;;
        -v|--verbose) VERBOSE="yes";;
        -g|--keygen) KEYGEN="yes"; RSA="no";;
        -s|--sign) SIGN="yes";;
        -e|--eddsa) EDDSA="yes"; RSA="no";;
        -r|--rsa) RSA="yes"; EDDSA="no";;
        -d|--related) RELATED=$2; shift;;
        -i|--relating) RELATING=$2; shift;;
        -p|--privdir) KEYDIR=$2; shift;;
        -t|--tag) TAG=$2; shift;;
        (--) shift; break;;
        (-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
        (*)  break;;
    esac
    shift
done

if [[ "x$RELATING" == "x" ]]
then
    echo "No relating domain specified - exiting"
    exit 1
fi

if [[ "x$OBIN" == "x" ]]
then
    echo "Can't find openssl binary - exiting"
    exit 1
fi

# prep values for zone fragment, these could be parameterised
# later, but later is fine
RDBD_RRTYPE="TYPE65443"
RDBDKEY_RRTYPE="TYPE65448"
TTL="3600"

# check if we have relevant keys, files are named after hash of
# Relating-domain (in case of i18n and for fun:-)
hashname=`echo -e "$RELATING" | $OBIN sha256 | awk '{print $2}'`
privfilename=$KEYDIR/$hashname.priv
pubfilename=$KEYDIR/$hashname.pub
if [[ "$KEYGEN" == "yes" ]]
then
    if [ ! -d $KEYDIR ]
    then
        mkdir -p $KEYDIR
    fi
    KEYPARMS=""
    if [[ "$EDDSA" == "yes" ]]
    then
        # 32 random octets are good enough
        dd if=/dev/urandom count=32 bs=1 >$privfilename 2>/dev/null
        if [ ! -f $privfilename ]
        then
            echo "Could't make private key file for $RELATING - exiting"
            exit 3
        fi
        fsz=`wc -c $privfilename | awk '{print $1}'`
        if [[ "$fsz" != "32" ]]
        then
            echo "Private key file for $RELATING is weird size - exiting"
            echo "Offending file is $privfilename"
            exit 4
        fi
        $RDIR/ed25519-makekey.py -s $privfilename -p $pubfilename 
        if [ ! -f $pubfilename ]
        then
            echo "Something went wrong generating a key pair - exiting"
            exit 5
        fi
        b64pub=`base64 -w 0 $pubfilename`
        KEYPARMS=" -a 15 -p $b64pub"
    elif [[ "$RSA" == "yes" ]]
    then
        $OBIN genrsa -out $privfilename 2048 >/dev/null 2>&1
        $OBIN rsa -in $privfilename -out $pubfilename -pubout -outform PEM >/dev/null 2>&1
        if [ ! -f $pubfilename ]
        then
            echo "Something went wrong generating a key pair - exiting"
            exit 5
        fi
        # b64 decode then re-encode to get rid of PEMery
        b64pub=`cat $pubfilename | sed -e '/----.*PUBLIC KEY----\|^[[:space:]]*$/d' | base64 -d | base64 -w 0`
        KEYPARMS=" -a 8 -p $b64pub"
    fi
    # output zone file fragment with public key
    $RDIR/encode-zfs.py -T $RDBDKEY_RRTYPE -o $RELATING. -t $TTL $KEYPARMS
    # And we're done generating a key pair
    exit 0
fi

# if we get here we should also have a related domain
if [[ "x$RELATED" == "x" ]]
then
    echo "No related domain specified - exiting"
    exit 1
fi

SIGPARMS=""
if [[ "$SIGN" == "yes" ]]
then
    if [ ! -f $privfilename ]
    then
        echo "Can't access private key - exiting"
        exit 5
    fi
    if [ ! -f $pubfilename ]
    then
        echo "Can't access public key - exiting"
        exit 6
    fi
    TMPSIG=`mktemp`
    if [[ "$EDDSA" == "yes" ]]
    then
        PUB=`base64 $pubfilename`
        KEYID=`$RDIR/keytag3.py -a 15 -p $PUB`
        sigalg="15"
        tbs="relating=$RELATING\nrelated=$RELATED\nrdbd-tag=$TAG\nkey-tag=$KEYID\nsig-alg=$sigalg\n"
        $RDIR/ed25519-signer.py -s $privfilename -m $tbs -o $TMPSIG
        b64sig=`base64 -w 0 $TMPSIG`
    elif [[ "$RSA" == "yes" ]]
    then
        PUB=`cat $pubfilename | awk '!/----/' | tr '\n' ' ' | sed -e 's/ //g'`
        KEYID=`$RDIR/keytag3.py -a 8 -p $PUB`
        sigalg="8"
        tbs="relating=$RELATING\nrelated=$RELATED\nrdbd-tag=$TAG\nkey-tag=$KEYID\nsig-alg=$sigalg\n"
        TMPTBS=`mktemp`
        echo -e $tbs >$TMPTBS
        $OBIN dgst -sha256 -sign $privfilename -out $TMPSIG $TMPTBS
        rm -f $TMPTBS
        b64sig=`base64 -w 0 $TMPSIG`
    fi
    rm -f $TMPSIG
    SIGPARMS=" -k $KEYID -a $sigalg -s $b64sig"
fi

# if the Related-domain is actually a URL then the we want the record to go into
# the Relating-domain zone
URL="no"
if [[ $RELATED == https://* ]]
then
    URL="yes"
fi

# output zone file fragment with or without signature
if [[ "$TAG" == "0" ]]
then
    # other than URLs the only semantic we know is the negative disavowal one
    # in which case the fragment goes into the Relating-domain 
    # zone file
    if [[ "$URL" == "yes" ]]
    then
        # URLs don't get a trailing dot:-)
        $RDIR/encode-zfs.py -T $RDBD_RRTYPE -o $RELATING. -t $TTL -g $TAG -r $RELATED $SIGPARMS
    else
        $RDIR/encode-zfs.py -T $RDBD_RRTYPE -o $RELATING. -t $TTL -g $TAG -r $RELATED. $SIGPARMS
    fi
else
    if [[ "$URL" == "yes" ]]
    then
        $RDIR/encode-zfs.py -T $RDBD_RRTYPE -o $RELATING. -t $TTL -g $TAG -r $RELATED $SIGPARMS
    else
        $RDIR/encode-zfs.py -T $RDBD_RRTYPE -o $RELATED. -t $TTL -g $TAG -r $RELATING. $SIGPARMS
    fi
fi


