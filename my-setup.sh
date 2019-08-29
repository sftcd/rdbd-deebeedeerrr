#!/bin/bash

# set -x

# call make-zonefrags.sh for the various domains about which I 
# (the author:-) care - these are some domains operated by Tolerant 
# Networks Limited. (https://tolerantnetworks.com/)

RDIR="$HOME/code/rdbd-deebeedeerrr"
BIN="$RDIR/make-zonefrags.sh"

# places for things
export KEYDIR="$RDIR/keys"
export ZFDIR="$RDIR/zonefrags"

# generate new key pairs for our main .com and .ie domains
$BIN -g --rsa -i tolerantnetworks.com >>$ZFDIR/tolerantnetworks.com.zone
$BIN -g -i tolerantnetworks.ie >>$ZFDIR/tolerantnetworks.ie.zone

# assert both are related (bidirectionally), both are DNSSEC
# signed so the signature is just for fun really:-)
$BIN -s --rsa -i tolerantnetworks.com -d tolerantnetworks.ie  >>$ZFDIR/tolerantnetworks.ie.zone
$BIN -s -i tolerantnetworks.ie -d tolerantnetworks.com  >>$ZFDIR/tolerantnetworks.com.zone

# Make other assertions related to my-own.ie and my-own.net 
# which are ours. We also disavow my-own.com which is not ours.
$BIN -i tolerantnetworks.ie -d my-own.ie >>$ZFDIR/my-own.ie.zone
$BIN -i tolerantnetworks.ie -d my-own.net  >>$ZFDIR/my-own.net.zone
$BIN -i tolerantnetworks.ie -d https://tolerantnetworks.com/rdbdeze.json >>$ZFDIR/tolerantnetworks.ie.zone
$BIN -t 0 -i tolerantnetworks.ie -d my-own.com >>$ZFDIR/tolerantnetworks.ie.zone
