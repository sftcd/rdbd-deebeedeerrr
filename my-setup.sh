#!/bin/bash

# call make-zone.sh for the various domains about which I (the 
# author:-) care
RDIR="$HOME/code/rdbd-deebeedeerrr"
BIN="$RDIR/make-zonefrag.sh"

# places for things
export PRIVKEYDIR="$RDIR/keys"
export ZFDIR="$RDIR/zonefrags"

$BIN -i tolerantnetworks.com -d tolerantnetworks.ie 
$BIN -i tolerantnetworks.com -d my-own.ie 
$BIN -i tolerantnetworks.com -d my-own.net 
$BIN -t 0 -i tolerantnetworks.com -d my-own.com 
$BIN -s -i tolerantnetworks.com -d hoba.ie 

$BIN -i tolerantnetworks.ie -d tolerantnetworks.com 
$BIN -sr -i tolerantnetworks.ie -d hoba.ie 
