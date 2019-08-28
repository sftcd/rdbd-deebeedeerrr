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

function rdbd_present()
{
    line=$*
    if [[ "$line" == *"TYPE65443"* ]]
    then
        newline=${line/TYPE65443/RDBD}
        echo "Foo: $newline"
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
