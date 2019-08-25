#!/bin/bash

# set -x

# call make-zone.sh for the various domains about which I (the 
# author:-) care
RDIR="$HOME/code/rdbd-deebeedeerrr"
BIN="$RDIR/make-zonefrags.sh"

# places for things
export KEYDIR="$RDIR/keys"
export ZFDIR="$RDIR/zonefrags"

# generrate new key pairs 
$BIN -g -i tolerantnetworks.com >>$ZFDIR/tolerantnetworks.com.zone
$BIN -g --rsa -i tolerantnetworks.ie >>$ZFDIR/tolerantnetworks.ie.zone

$BIN -i tolerantnetworks.com -d tolerantnetworks.ie  >>$ZFDIR/tolerantnetworks.ie.zone
$BIN -i tolerantnetworks.com -d my-own.ie >>$ZFDIR/my-own.ie.zone
$BIN -i tolerantnetworks.com -d my-own.net  >>$ZFDIR/my-own.net.zone
$BIN -t 0 -i tolerantnetworks.com -d my-own.com >>$ZFDIR/tolerantnetworks.com.zone
$BIN -s -i tolerantnetworks.com -d hoba.ie  >>$ZFDIR/hoba.ie.zone

$BIN -i tolerantnetworks.ie -d tolerantnetworks.com  >>$ZFDIR/tolerantnetworks.com.zone
$BIN --sign --rsa -i tolerantnetworks.ie -d hoba.ie  >>$ZFDIR/hoba.ie.zone
