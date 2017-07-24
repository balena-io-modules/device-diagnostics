#!/bin/bash

# Determine whether we're using the older 'rce'-aliased docker or not.
docker_name=$(which docker >/dev/null && echo "docker" || echo "rce")

# docker's mount is also the core btrfs filesystem.
mountpoint="/var/lib/$docker_name"

low_mem_threshold=10 #%
low_disk_threshold=10 #%
low_metadata_threshold=30 #%

# DIAGNOSTIC COMMANDS BELOW.
commands=(
	"cat /etc/os-release"
	"uname -a"
	"free -h"
	"cat /proc/cpuinfo"
	"cat /proc/meminfo"
	"ps"
	"top -b -n 1"
	"tail -500 /var/log/supervisor-log/resin_supervisor_stdout.log" # legacy
	"cat /var/log/provisioning-progress.log"
	"df -h"
	"btrfs fi df /mnt/data-disk" # legacy
	"btrfs fi df /mnt/data"
	"btrfs fi usage /mnt/data-disk" # legacy
	"btrfs fi usage /mnt/data"
	"cat /mnt/data-disk/config.json | jq '.apiKey = \"foo\" | .deviceApiKey = \"bar\" | .pubnubSubscribeKey = \"psk\" | .pubnubPublishKey = \"ppk\" | .mixpanelToken = \"mpt\" | .wifiKey = \"dunno\" | .files = {}'"  # legacy
	"cat /mnt/conf/config.json | jq '.apiKey = \"foo\" | .deviceApiKey = \"bar\" | .pubnubSubscribeKey = \"psk\" | .pubnubPublishKey = \"ppk\" | .mixpanelToken = \"mpt\" | .wifiKey = \"dunno\" | .files = {}'" # legacy
	"cat /mnt/boot/config.json | jq '.apiKey = \"foo\" | .deviceApiKey = \"bar\" | .pubnubSubscribeKey = \"psk\" | .pubnubPublishKey = \"ppk\" | .mixpanelToken = \"mpt\" | .wifiKey = \"dunno\" | .files = {}'"
	"ls -l /mnt/boot/system-connections"
	"cat /mnt/boot/config.txt" # only for rpi...
	"cat /mnt/boot/uEnv.txt" # only for uboot devices
	"cat /mnt/boot/resinOS_uEnv.txt" # ibidem
	"mount"
	"ls -l /dev"
	"date"
	"timedatectl status"
	"/sbin/ip addr"
	"curl https://www.google.co.uk"
	"curl https://pubnub.com"
	"curl https://api.resin.io/ping"
	"journalctl -n500"
	"dmesg"
	"cat /var/log/messages" # legacy
	"cat /etc/resolv.conf"
	"cat /proc/net/dev"
	"cat /proc/net/udp"
	"cat /proc/net/snmp"
	"netstat -ntl"
	"curl --max-time 5 localhost:48484/ping"
	"$docker_name --version"
	"ping -c 1 -W 3 google.co.uk"
	"$docker_name images"
	"$docker_name ps -a"
	"$docker_name stats --all --no-stream"
	"systemctl status resin-supervisor"
	"journalctl -n 200 --no-pager -u resin-supervisor"
	"systemctl status $docker_name"
	"journalctl -n 200 --no-pager -u $docker_name"
	"systemctl status openvpn-resin"
	"journalctl -n 200 --no-pager -u openvpn-resin"
	"iptables -n -L"
	"iptables -n -t nat -L"
	"$docker_name exec resin_supervisor cat /etc/resolv.conf"
)

function each_command()
{
	local meta_command=$1
	for command in "${commands[@]}"
	do
		eval "$1 \"$command\""
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

function announce_version()
{
	announce "leech / diagnose ${LEECH_VERSION}"
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

function is_mounted()
{
	# busybox grep doesn't like long options.
	mount | grep -q "on $1"
}

function check_memory()
{
	total_kb=$(get_meminfo_field MemTotal)
	avail_kb=$(get_meminfo_field MemAvailable)

	if [ -z "$avail_kb" ]; then
		# For kernels that don't support MemAvailable.
		# Not as accurate, but a good approximation.

		avail_kb=$(get_meminfo_field MemFree)
		avail_kb=$((avail_kb + $(get_meminfo_field Cached)))
		avail_kb=$((avail_kb + $(get_meminfo_field Buffers)))
	fi

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
	if ! is_mounted $mountpoint; then
		echo "DISK: DANGER: BTRFS filesystem not mounted at $mountpoint!"
		return
	fi

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
	if ! is_mounted $mountpoint; then
		echo "METADATA: SKIP: BTRFS filesystem not mounted."
		return
	fi

	read total used <<<$(btrfs_get_data $mountpoint "Metadata, DUP")

	used_percent=$((used*100/total))
	free_percent=$((100 - $used_percent))

	if [ "$free_percent" -lt "$low_metadata_threshold" ]; then
		echo "METADATA: DANGER: LOW SPACE: ${free_percent}% btrfs metadata free."
	else
		echo "METADATA: OK (${free_percent}% btrfs metadata free.)"
	fi
}

function check_docker()
{
	if (pidof $docker_name >/dev/null); then
		echo "DOCKER: OK (docker is running.)"
	else
		echo "DOCKER: DANGER: docker is NOT running!"
	fi
}

function check_supervisor()
{
	container_running=$($docker_name ps | grep resin_supervisor)
	if [ -z "$container_running" ]; then
		echo "SUPERVISOR: DANGER (supervisor is NOT running!)"
	else
		echo "SUPERVISOR: OK (supervisor is running)."
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

	echo "DNS: OK (first DNS server is ${first_server}.)"
}

function run_checks()
{
	announce CHECKS

	check_memory
	check_docker
	check_supervisor
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

announce_version
run_checks
run_commands

# Don't return a spurious error code.
true
