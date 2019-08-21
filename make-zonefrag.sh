#!/bin/bash

# set -x

# Call our zonefile fragment producer code for each
# relevant relationship (or disavowal)

# This code assumes that the private key for a specific
# Relating-domain "R" is stored in $PRIVKEYDIR/hash(R).priv
# The hashing is so that we don't need to worry about
# i18n for file names.
# If such a private key file exists, we'll use that and
# not overwrite public key values

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
: "${PRIVKEYDIR:="."}"
: "${ZFDIR:="."}"
: "${VERBOSE:="no"}"
: "${TAG:="1"}"
: "${SIGN:="no"}"
: "${EDDSA:="yes"}"
: "${RSA:="no"}"
: "${OBIN=`which openssl`}"
: "${PASS="arse"}"

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
        -p|--privdir) PRIVKEYDIR=$2; shift;;
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

if [[ "$SIGN" == "yes" ]]
then
    if [ ! -d $PRIVKEYDIR ]
    then
        mkdir -p $PRIVKEYDIR
    fi

    hashname=`echo -e "$RELATING" | $OBIN sha256 | awk '{print $2}'`
    privfilename=$PRIVKEYDIR/$hashname.priv
    if [ ! -f $privfilename ]
    then
        echo "Can't read $privfilename (based on $RELATING) - making one"
        if [[ "$EDDSA" == "yes" ]]
        then
            # 32 random octets are good enough
            dd if=/dev/urandom count=32 bs=1 >$privfilename
        fi
        if [[ "$RSA" == "yes" ]]
        then
            $OBIN req -batch -new -x509 -days 3650 \
	            -newkey rsa:2048 -keyout $privfilename  -out $PRIVKEYDIR/$hashname.csr  \
	            -config /etc/ssl/openssl.cnf -passin pass:$PASS \
	            -subj "/C=IE/ST=Laighin/O=rdbd/CN=$RELATING" \
	            -passout pass:$PASS 
        fi
    fi
fi

# ok, inputs are validated, time to do stuff...
