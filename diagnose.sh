#!/bin/bash

# rce's mount is also the core btrfs filesystem.
mountpoint="/var/lib/rce"

low_mem_threshold=10 #%
low_disk_threshold=10 #%
low_metadata_threshold=30 #%

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
	"cat /etc/resolv.conf"
	"cat /proc/net/dev"
	"cat /proc/net/udp"
	"cat /proc/net/snmp"
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

function announce()
{
	echo
	echo "--- $@ ---"
	echo
}

# Sadly set -x outputs to stderr and with redirection the interleaving gets
# screwed up :( let's do manually for now.
function announce_run()
{
	announce $@
	eval $@ 2>&1
}

function get_meminfo_field()
{
	# Thankfully this works even with busybox :)
	cat /proc/meminfo | grep "^$1:" | awk '{print $2}'
}

function btrfs_get_data()
{
	btrfs fi df --raw $1 \
	    | grep "^$2" \
	    | grep -o '[0-9]*' \
	    | paste - -
}

function check_memory()
{
	total_kb=$(get_meminfo_field MemTotal)
	avail_kb=$(get_meminfo_field MemAvailable)

	total_mb=$((total_kb/1024))
	avail_mb=$((avail_kb/1024))

	used_mb=$((total_mb - avail_mb))
	percent=$((100*avail_kb/total_kb))

	if [ "$percent" -lt "${low_mem_threshold}" ]; then
	    echo "MEM: DANGER: LOW MEMORY: ${percent}% (${avail_mb}MB) available. ${used_mb}MB/${total_mb}MB used."
	else
	    echo "MEM: OK (${percent}% available.)"
	fi
}

function check_diskspace()
{
	# Last +0 forces the field to a number, stripping the '%' on the end.
	# Tested working on busybox.
	used_percent=$(df $mountpoint | tail -n 1 | awk '{print $5+0}')
	free_percent=$((100 - $used_percent))

	# First, check that df indicates low space. If not, no need to check
	# btrfs df. This is because btrfs allocates more space than is needed,
	# so df saying we're out of space doesn't mean we actually are.
	if [ "$free_percent" -gt "$low_disk_threshold" ]; then
	    echo "DISK: OK (df reports ${free_percent}% free.)"
	    return
	fi

	read total used <<<$(btrfs_get_data $mountpoint "Data, single")

	used_percent_btrfs=$((used*100/total))
	free_percent_btrfs=$((100 - $used_percent_btrfs))

	if [ "$free_percent_btrfs" -lt "$low_disk_threshold" ]; then
	    echo "DISK: DANGER: LOW SPACE: df reports ${free_percent}%, btrfs reports ${free_percent_btrfs}%."
	else
	    echo "DISK: OK (df reports ${free_percent}% free, but btrfs reports ${free_percent_btrfs}% free.)"
	fi
}

function check_metadata()
{
	read total used <<<$(btrfs_get_data $mountpoint "Metadata, DUP")

	used_percent=$((used*100/total))
	free_percent=$((100 - $used_percent))

	if [ "$free_percent" -lt "$low_metadata_threshold" ]; then
	    echo "METADATA: DANGER: LOW SPACE: ${free_percent}% btrfs metadata free."
	else
	    echo "METADATA: OK (${free_percent}% btrfs metadata free.)"
	fi
}

function check_rce()
{
	if (pidof rce >/dev/null); then
	    echo "RCE: OK (rce is running.)"
	else
	    echo "RCE: DANGER: rce is NOT running!"
	fi
}

function check_dns()
{
	if [ ! -f /etc/resolv.conf ]; then
	    echo "DNS: DANGER: /etc/resolv.conf missing!!"
	    return
	fi

	first_server=$(cat /etc/resolv.conf | \
				  grep "^nameserver" | \
				  head -n 1 | \
				  awk '{print $2}')

	if [ "$first_server" = "8.8.8.8" ] || [ "$first_server" = "8.8.4.4" ]; then
	    echo "DNS: OK (first DNS server is ${first_server}.)"
	else
	    echo "DNS: DANGER: First DNS server not google, is '${first_server}'."
	fi
}

function run_checks()
{
	announce CHECKS

	check_memory
	check_rce
	check_dns
	check_diskspace
	check_metadata
}

function run_commands()
{
	announce COMMANDS
	# List commands.
	each_command echo
	# announce each command, then run it.
	each_command announce_run
}

run_checks
run_commands
