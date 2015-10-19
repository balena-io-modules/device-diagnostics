#!/bin/bash

# DIAGNOSTIC COMMANDS BELOW.
commands=(
	"uname -a"
	"free -h"
	"cat /proc/cpuinfo"
	"cat /proc/meminfo"
	"ps"
	"top -b -n 1"
	"tail -500 /var/log/supervisor-log/resin_supervisor_stdout.log"
	"cat /var/log/provisioning-progress.log"
	"df -h"
	"btrfs fi df /mnt/data-disk" # legacy
	"btrfs fi df /mnt/data"
	"cat /mnt/data-disk/config.json" # legacy
	"cat /mnt/conf/config.json"
	"mount"
	"ls -l /dev"
	"date"
	"/sbin/ip addr"
	"curl https://google.co.uk"
	"ping -c 1 -W 3 google.co.uk"
	"journalctl -n500"
	"dmesg"
	"cat /var/log/messages" # legacy
	"rce --version"
	"rce images"
	"rce ps -a"
)

function each_command()
{
	for command in "${commands[@]}"
	do
		eval "$1 $command"
	done
}

# Sadly set -x outputs to stderr and with redirection the interleaving gets
# screwed up :( let's do manually for now.
function announce_run()
{
	echo
	echo "--- $@ ---"
	echo
	eval $@ 2>&1
}

EXPECTED_UUID=@@replaceme@@
UUID=$(head -1 /var/volatile/vpnfile)

if [ "$UUID" != "$EXPECTED_UUID" ]; then
   echo "ERROR: This is not the device you are looking for."
   echo "ERROR: Expected: $EXPECTED_UUID"
   echo "ERROR:   Actual: $UUID"
   exit 1
fi

echo "--- COMMANDS ---"
echo
each_command echo
# Prepend with 'd' due to issues with set -x.
each_command announce_run
