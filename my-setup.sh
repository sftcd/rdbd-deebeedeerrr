#!/bin/bash

# call make-zone.sh for the various domains about which I (the 
# author:-) care
BIN="$HOME/code/rdbd-deebeedeerrr/make-zonefrag.sh"

$BIN -i tolerantnetworks.com -e tolerantnetworks.ie 
$BIN -i tolerantnetworks.com -e my-own.ie 
$BIN -i tolerantnetworks.com -e my-own.net 
$BIN -t 0 -i tolerantnetworks.com -e my-own.com 
$BIN -s -i tolerantnetworks.com -e hoba.ie 
