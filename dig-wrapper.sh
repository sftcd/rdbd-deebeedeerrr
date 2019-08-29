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
        # if 0000 then unrelated, other values we
        # don't understand
        if [[ "$rrvalue" == "" ]]
        then
            # the query line
            echo $newline
        elif [[ "$rrvalue" == 0000* ]]
        then
            echo "$leader UNRELATED $rrlen $rrvalue"
        elif [[ "$rrvalue" == 0001* ]]
        then
            echo "$leader RELATED $rrlen $rrvalue"
        else
            echo "$leader RBDB-TAG:[${rrvalue0:3}] $rrlen $rrvalue"
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
