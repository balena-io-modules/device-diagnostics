#!/bin/bash

# Sadly set -x outputs to stderr and with redirection the interleaving gets
# screwed up :( let's do manually for now.
function d()
{
	echo
	echo "--- $@ ---"
	echo
	eval $@
}

EXPECTED_UUID=@@replaceme@@

UUID=$(head -1 /var/volatile/vpnfile)

if [ "$UUID" != "$EXPECTED_UUID" ]; then
   echo "ERROR: This is not the device you are looking for."
   echo "ERROR: Expected: $EXPECTED_UUID"
   echo "ERROR:   Actual: $UUID"
   exit 1
fi

# DIAGNOSTIC COMMANDS BELOW.
# Prepend with 'd' due to issues with set -x.

d free -h
d cat /proc/meminfo
d ps
d top -b -n 1
