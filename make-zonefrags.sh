#!/bin/bash

# set -x

# Call our zonefile fragment producer code for each
# key and relevant relationship (or disavowal)

# This code assumes that the private key for a specific
# Relating-domain "R" is stored in $KEYDIR/hash(R).priv
# The hashing is so that we don't need to worry about
# i18n for file names.
# If such a private key file exists, we'll use that and
# not overwrite public key values

# set directories
RDIR="$HOME/code/rdbd-deebeedeerrr"

function usage()
{
	echo "$0 -i relating-domain -d related-domain [-t tag-no ] [-p privkeydir] [-ershv]"
    echo ""
    echo "Create the relevant zonefile fragments matching the ipnputs"
    echo "-h - produce this"
    echo "-v - be verbose"
    echo "-r - use RSA"
    echo "-e - use EdDSA"
    echo "-i - specify the relating domain to use"
    echo "-d - specify the related domain to use"
    echo "-p - specify the private key file directory"
    echo "-t - specify the rdbd-tag value to use (1=avow, 0=disavow, default is 1)"
    echo "-s - make a digital signature for this"
	exit 99
}

function hashname()
{
    name=$1
    hash=`echo -e $name  | openssl sha256` 
}

# Set default values if not already set in the environment
: "${KEYDIR:="."}"
: "${ZFDIR:="."}"
: "${VERBOSE:="no"}"
: "${TAG:="1"}"
: "${SIGN:="no"}"
: "${EDDSA:="yes"}"
: "${RSA:="no"}"
: "${OBIN=`which openssl`}"

# set blank values
RELATING=""
RELATED=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o i:d:p:t:z:shver -l relating:,related:,privdir:,tag:,zdir,sign,help,verbose,eddsa,rsa -- "$@")
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
        -s|--sign) SIGN="yes";;
        -e|--eddsa) EDDSA="yes"; RSA="no";;
        -r|--rsa) RSA="yes"; EDDSA="no";;
        -d|--related) RELATED=$2; shift;;
        -z|--zdir) ZFDIR=$2; shift;;
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

if [[ "x$RELATED" == "x" ]]
then
    echo "No related domain specified - exiting"
    exit 1
fi

if [ ! -d $ZFDIR ]
then
    mkdir -p $ZFDIR
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
if [[ "$SIGN" == "yes" ]]
then
    if [ ! -d $KEYDIR ]
    then
        mkdir -p $KEYDIR
    fi
    if [[ "$EDDSA" == "yes" ]]
    then
        if [ ! -f $privfilename ]
        then
            #echo "Can't read private key file for $RELATING - making one"
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
            # output zone file fragment with public key
            b64pub=`base64 -w 48 $pubfilename  | sed -e 's/^/            /'`
            echo -e "$RELATING. $TTL IN $RDBDKEY_RRTYPE 0 3 8 (\n$b64pub)"
        fi
        if [ ! -f $pubfilename ]
        then
            echo "Something went wrong generating a key pair - exiting"
            exit 5
        fi
        PUB=`base64 $pubfilename`
        KEYID=`$RDIR/keytag3.py -a 15 -p $PUB`
        sigalg="15"
        tbs="relating=$RELATING\nrelated=$RELATED\nrdbd-tag=$TAG\nkey-tag=$KEYID\nsig-alg=$sigalg\n"
        TMPSIG=`mktemp`
        $RDIR/ed25519-signer.py -s $privfilename -m $tbs -o $TMPSIG
        b64sig=`base64 -w 48 $TMPSIG  | sed -e 's/^/            /'`
        rm -f $TMPSIG
    elif [[ "$RSA" == "yes" ]]
    then
        if [ ! -f $privfilename ]
        then
            #echo "Can't read private key file for $RELATING - making one"
            $OBIN genrsa -out $privfilename 2048 >/dev/null 2>&1
            $OBIN rsa -in $privfilename -out $pubfilename -pubout -outform PEM >/dev/null 2>&1
            # output zone file fragment with public key
            b64pub=`base64 -w 48 $pubfilename  | sed -e 's/^/            /'`
            echo -e "$RELATING. $TTL IN $RDBDKEY_RRTYPE 0 3 8 (\n$b64pub)"
        fi
        if [ ! -f $pubfilename ]
        then
            echo "Something went wrong generating a key pair - exiting"
            exit 5
        fi
        PUB=`cat $pubfilename | awk '!/----/' | tr '\n' ' ' | sed -e 's/ //g'`
        KEYID=`$RDIR/keytag3.py -a 8 -p $PUB`
        sigalg="8"
        tbs="relating=$RELATING\nrelated=$RELATED\nrdbd-tag=$TAG\nkey-tag=$KEYID\nsig-alg=$sigalg\n"
        TMPTBS=`mktemp`
        echo -e $tbs >$TMPTBS
        TMPSIG=`mktemp`
        $OBIN dgst -sha256 -sign $privfilename -out $TMPSIG $TMPTBS
        rm -f $TMPTBS
        b64sig=`base64 -w 48 $TMPSIG  | sed -e 's/^/            /'`
        rm -f $TMPSIG
    fi
    SIGFRAG=" $KEYID $sigalg (\n$b64sig )"
fi

# output zone file fragment with or without signature
if [[ "$TAG" == "0" ]]
then
    # the only real semantic we know is the negative disavowal one
    # in which case the fragment goes into the Relating-domain 
    # zone file
    echo -e "$RELATING.\t\t$TTL IN $RDBD_RRTYPE $TAG $RELATED. $SIGFRAG"
else
    echo -e "$RELATED.\t\t$TTL IN $RDBD_RRTYPE $TAG $RELATING. $SIGFRAG"
fi


