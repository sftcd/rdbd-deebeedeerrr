#!/bin/bash

# set -x

# A wrapper around dig that knows how to handle the 
# proposed new RR types from draft-brotman-rdbd

# This just uses a bit of primitive pattern matching
# but that's ok, it's just a POC

params=" $* "

: "${OBIN=`which openssl`}"
: "${RDIR="$HOME/code/rdbd-deebeedeerrr"}"

# For testing, setting this will break signatures, thus providing
# confidence that when it says "good" that's more likely true:-)
: "${SIGBREAK="no"}"

doing_something=false
doing_rdbd=false
doing_rdbdkey=false

if [[ "$params" == *" RDBD "* ]]
then
    doing_something=true
    doing_rdbd=true
    params=${params/ RDBD / TYPE65443 }
fi
if [[ "$params" == *" TYPE65443 "* ]]
then
    doing_something=true
    doing_rdbd=true
fi
if [[ "$params" == *" RDBDKEY "* ]]
then
    doing_something=true
    doing_rdbdkey=true
    params=${params/ RDBDKEY / TYPE65448 }
fi
if [[ "$params" == *" TYPE65448 "* ]]
then
    doing_something=true
    doing_rdbdkey=true
fi

if [ "$doing_something" = false ]
then
    dig $params
    exit $?
fi

if [[ "$SIGBREAK" == "yes" ]]
then
    echo "BREAKING SIGNATURES as requested!!"
fi

# extract RR value from dig line output - can be space
# separated set of values from the 7th word on the line
# to the end
function extract_rrvalue()
{
    line=$*
    rrvalue=""
    count=0
    for word in $line
    do
        if ((count>=6))
        then
            rrvalue="$rrvalue$word"
        fi
        count=$((count+1))
    done
    echo $rrvalue
}

function extract_related()
{
    related=""
    rrval=${1:4}
    rrlen=${#rrval}
    # value now should start with ascii-hex of a length prefix string 
    # containing an https URL or a wire-format DNS name
    ah_label_len=${rrval:0:2}
    # convert ascii-hex to decimal
    label_len=`printf "%d" 0x$ah_label_len`
    offset=2
    chars_remaining=$((rrlen-offset))
    while ((label_len!=0 && chars_remaining>0))
    do
        label_enc_len=$((label_len*2))
        enc_label=${rrval:$offset:$label_enc_len}
        label=`echo $enc_label | xxd -r -p`
        if [[ "$related" == "" ]]
        then
            related="$label"
        else
            related="$related.$label"
        fi
        offset=$((offset+label_enc_len))
        ah_label_len=${rrval:$offset:2}
        label_len=`printf "%d" 0x$ah_label_len`
        offset=$((offset+2))
        chars_remaining=$((rrlen-offset))
    done
    if ((chars_remaining > 0))
    then
        # that should be a signature
        echo $related
        # add 4 to the return value - we skipped over those
        # bytes (the rdbd-tag) when setting the rrval value 
        # at the start
        return $((offset+4))
    else
        echo $related
        return 0
    fi
}

function verify_rsasig()
{
    tbs=$1
    b64sig=$2
    # add line breaks as openssl likes 'em
    b64pub=`echo $3 | base64 -d | base64 -w64`
    TMPSIG=`mktemp`
    echo $b64sig | base64 -d >$TMPSIG
    TMPPUB=`mktemp`
    echo "-----BEGIN PUBLIC KEY-----" >$TMPPUB
    for word in $b64pub 
    do
        echo $word >>$TMPPUB
    done
    echo "-----END PUBLIC KEY-----" >>$TMPPUB
    TMPTBS=`mktemp`
    echo -e $tbs >$TMPTBS
    $OBIN dgst -sha256 -verify $TMPPUB -signature $TMPSIG $TMPTBS >/dev/null 2>&1
    sv=$?
    rm -f $TMPTBS $TMPPUB $TMPSIG
    if [[ "$sv" == "0" ]]
    then
        echo "Sig: good"
    else
        echo "Sig: bad"
    fi
}
        
function verify_ed25519()
{
    tbs=$1
    b64sig=$2
    b64pub=$3
    $RDIR/ed25519-signverify.py -p $b64pub -m $tbs -S $b64sig
    sv=$?
    if [[ "$sv" == "0" ]]
    then
        echo "Sig: good"
    else
        echo "Sig: bad"
    fi
}

function verify_sig()
{
    b64sig=$1 
    if [[ "$SIGBREAK" == "yes" ]]
    then
        # flip some signature bits to force a "bad" answer
        # we'll use the classic rot13 :-)
        b64sig=`echo $1 | tr 'A-Za-z' 'N-ZA-Mn-za-m'`
    fi
    qname=$2
    related=$3
    rel=$4
    keyid=$5
    alg=$6
    # get public key from DNS 
    if [[ "$rel" == "UNRELATED" ]]
    then
        # in unrelated case, public key is at relating which is qname
        publicans=`dig +short +split=0 TYPE65448 $qname | awk '{print $3}'`
        public_ah=${publicans:8}
        b64pub=`echo $public_ah | xxd -r -p | base64 -w0`
        tbs="relating=$qname\nrelated=$related\nrdbd-tag=0\nkey-tag=$keyid\nsig-alg=$alg\n"
    else
        # in related, or unknown cases, public key is at related (even though that's relating really:-)
        publicans=`dig +short +split=0 TYPE65448 $related | awk '{print $3}'`
        public_ah=${publicans:8}
        b64pub=`echo $public_ah | xxd -r -p | base64 -w0`
        if [[ "$rel" == "RELATED" ]]
        then
            rdbdtag="1"
        else
            # rel was made up as "RDBD-TAG:[${rrvalue:0:3}]"
            rdbdtag_ah=${rel:11:3}
            rdbdtag=`printf "%d" 0x$rdbdtag_ah`
        fi
        tbs="relating=$related\nrelated=$qname\nrdbd-tag=$rdbdtag\nkey-tag=$keyid\nsig-alg=$alg\n"
    fi
    if [[ "$alg" == "8" ]]
    then
        sigres=`verify_rsasig $tbs $b64sig $b64pub`
    elif [[ "$alg" == "15" ]]
    then
        sigres=`verify_ed25519 $tbs $b64sig $b64pub`
    else
        sigres="Sig: not checked"
    fi
    echo $sigres
}

function parse_sig()
{
    sigdets=$1
    qname=$2
    rel=$3
    related=$4
    hex_keyid=${sigdets:0:4}
    keyid=`printf "%d" 0x$hex_keyid`
    hex_alg=${sigdets:4:2}
    alg=`printf "%d" 0x$hex_alg`
    ah_sigbits=${sigdets:6}
    b64sig=`echo $ah_sigbits | xxd -r -p | base64 -w0`
    sv=`verify_sig $b64sig $qname $related $rel $keyid $alg`
    echo "$sv KeyId: $keyid Alg: $alg Sig: $b64sig"
}

function rdbd_present()
{
    line=$*
    if [[ "$line" == *"TYPE65443"* ]]
    then
        newline=${line/TYPE65443/RDBD}
        starter=`echo $newline | awk '{print $1," ",$2," ",$3," ",$4}'`
        qname=`echo $newline | awk '{print $1}' | sed -e 's/\.$//' `
        rrlen=`echo $newline | awk '{print $6}'`
        rrvalue=`extract_rrvalue $newline`
        if [[ "$rrvalue" == "" || "$newline" == *"DiG"* || "$newline" == *"RRSIG"* ]]
        then
            # if there's no value or it's the query string or an RRSIG then
            # we've done enough just replacing the TYPE65443 with RDBD
            echo $newline
        else
            # this is an RDBD answer, so parse it some...
            # if rrvalue starts with 0001 then related
            # if 0000 then unrelated, other tag values: we
            # don't understand 'em yet:-)
            rel="RDBD-TAG:[${rrvalue:0:3}]"
            if [[ "$rrvalue" == 0000* ]]
            then
                rel="UNRELATED"
            elif [[ "$rrvalue" == 0001* ]]
            then
                rel="RELATED"
            fi
            # extract the Related-domain field (a name or URL)
            # if there's also a signature present the function
            # will return the offset where we can find that
            # or zero if there's no signature
            related_domain=`extract_related $rrvalue`
            sigoff=$?
            if [[ "$sigoff" == "0" ]]
            then
                echo "$starter $rel $related_domain"
            else
                # parse signature a bit
                sigdets=`parse_sig ${rrvalue:$sigoff} $qname $rel $related_domain`
                echo "$starter $rel $related_domain $sigdets"
            fi
        fi
    else
        echo "$line"
    fi
}

function rdbdkey_present()
{
    line=$*
    if [[ "$line" == *"TYPE65448"* ]]
    then
        newline=${line/TYPE65448/RDBDKEY}
        starter=`echo $newline | awk '{print $1," ",$2," ",$3," ",$4}'`
        rrvalue=`extract_rrvalue $newline`
        if [[ "$rrvalue" == "" || "$newline" == *"DiG"* || "$newline" == *"RRSIG"* ]]
        then
            # if there's no value or it's the query string or an RRSIG then
            # we've done enough just replacing the TYPE65448 with RDBD
            echo $newline
        else
            hex_alg=${rrvalue:6:2}
            alg=`printf "%d" 0x$hex_alg`
            hex_pub=${rrvalue:8}
            b64pub=`echo $hex_pub | xxd -r -p | base64 -w0`
            echo "$starter Alg: $alg Public key: $b64pub"
        fi
    else
        echo "$line"
    fi
}

if [ "$doing_rdbd" = true ]
then
    dig $params | while read data
    do 
        rdbd_present $data
    done
fi

if [ "$doing_rdbdkey" = true ]
then
    dig $params | while read data
    do 
        rdbdkey_present $data
    done
fi
