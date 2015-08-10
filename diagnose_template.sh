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

d uname -a
d free -h
d cat /proc/cpuinfo
d cat /proc/meminfo
d ps
d top -b -n 1
d rce --version
d rce images
d rce ps
d tail -500 /var/log/supervisor-log/resin_supervisor_stdout.log
d df -h
d btrfs fi df /mnt/data-disk
d cat /mnt/data-disk/config.json
d mount
d ls -l /dev
d date
d /sbin/ip addr
d curl https://google.co.uk
d ping -c 1 -W 3 google.co.uk
