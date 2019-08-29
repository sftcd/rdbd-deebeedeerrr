#!/bin/bash

# set -x

# A wrapper around dig that knows how to handle the 
# proposed new RR types from draft-brotman-rdbd

# This just uses a bit of primitive pattern matching
# but that's ok, it's just a POC

params=" $* "

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
    chars_remaining=$rrlen
    # value now should start with ascii-hex of a length prefix string 
    # containing an https URL or a wire-format DNS name
    label_len=${rrval:0:2}
    # convert ascii-hex to decimal
    label_len=`printf "%d" 0x$label_len`
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
        label_len=${rrval:$offset:2}
        offset=$((offset+2))
        chars_remaining=$((rrlen-offset))
    done
    if ((chars_remaining > 0))
    then
        # that should be a signature
        echo $related
        return $((offset+4))
    else
        echo $related
        return 0
    fi
}

function parse_sig()
{
    sigdets=$1
    hex_keyid=${sigdets:0:4}
    keyid=`printf "%d" 0x$hex_keyid`
    hex_alg=${sigdets:4:2}
    alg=`printf "%d" 0x$hex_alg`
    ah_sigbits=${sigdets:3}
    b64sig=`echo $ah_sigbits | xxd -r -p | base64 -w0`
    echo "KeyId: $keyid Alg: $alg Sig: $b64sig"
}

function rdbd_present()
{
    line=$*
    if [[ "$line" == *"TYPE65443"* ]]
    then
        newline=${line/TYPE65443/RDBD}
        leader=`echo $newline | awk '{print $1," ",$2," ",$3," ",$4}'`
        rrlen=`echo $newline | awk '{print $6}'`
        rrvalue=`extract_rrvalue $newline`
        # if rrvalue starts with 0001 then related
        # if 0000 then unrelated, other tag values: we
        # don't understand 'em yet:-)
        if [[ "$rrvalue" == "" || "$newline" == *"DiG"* ]]
        then
            # the query line
            echo $newline
        else
            rel="RDBD-TAG:[${rrvalue:0:3}]"
            if [[ "$rrvalue" == 0000* ]]
            then
                rel="UNRELATED"
            elif [[ "$rrvalue" == 0001* ]]
            then
                rel="RELATED"
            fi
            related_domain=`extract_related $rrvalue`
            sigoff=$?
            #echo "related_domain: |$related_domain|"
            if [[ "$sigoff" == "0" ]]
            then
                echo "$leader $rel $related_domain"
            else
                # parse signature a bit
                sigdets=`parse_sig ${rrvalue:$sigoff}`
                echo "$leader $rel $related_domain $sigdets"
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
        echo "Bar: $newline"
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
