#!/bin/bash

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
	echo "$0 -i relating-domain -e related-domain [-t tag-no ] [-p privkeydir] [-shv]"
    echo ""
    echo "Create the relevant zonefile fragments matching the ipnputs"
    echo "-h - produce this"
    echo "-v - be verbose"
    echo "-i - specify the relating domain to use"
    echo "-e - specify the related domain to use"
    echo "-p - specify the private key file directory"
    echo "-t - specify the rdbd-tag value to use (1=avow, 0=disavow, default is 1)"
    echo "-s - make a digital signature for this"
	exit 99
}

function hashname()
{
    name=$1
    hash=`echo -e $naem  | openssl sha256` 
}

# Set default values if not already set in the environment
: "${PRIVKEYDIR:="."}"
: "${VERBOSE:="no"}"
: "${TAG:="1"}"
: "${SIGN:="no"}"

# set blank values
RELATING=""
RELATED=""

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o i:e:p:t:shv -l relating:,related:,privdir:,tag:,sign,help,verbose -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
#echo "|$options|"
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
        -e|--related) RELATED=$2; shift;;
		-h|--help) usage;;
        -i|--relating) RELATING=$2; shift;;
        -p|--privdir) PRIVKEYDIR=$2; shift;;
        -s|--sign) SIGN="yes";;
        -t|--tag) TAG=$2; shift;;
        -v|--verbose) VERBOSE="yes";;
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

if [ ! -d $PRIVKEYDIR ]
then
    echo "$PRIVKEYDIR doesn't exist - exiting"
    exit 1
fi

hashname=`echo -e "$RELATING" | openssl sha256 | awk '{print $2}'`
privfilename=$PRIVKEYDIR/$hashname.priv

if [ ! -f $privfilename ]
then
    echo "Can't read $privfilename (based on $RELATING)"
    # make a key pair
    exit 1
fi

# ok, inputs are validated, time to do stuff...
