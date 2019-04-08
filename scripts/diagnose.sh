#!/bin/bash
DIAGNOSE_VERSION=2.9.1
# Determine whether we're using the older 'rce'-aliased docker or not.
# stolen directly from the proxy:
# (https://github.com/balena-io/resin-proxy/blob/master/src/common/host-scripts.ts#L28)
X=/usr/bin/
ENG=rce
[ -x $X$ENG ] || ENG=docker
[ -x $X$ENG ] || ENG=balena
[ -x $X$ENG ] || ENG=balena-engine

# docker's mount is also the core btrfs filesystem.
mountpoint="/var/lib/$ENG"

low_mem_threshold=10 #%
low_disk_threshold=10 #%
low_metadata_threshold=30 #%

slow_disk_write=1000 #ms

## DIAGNOSTIC COMMANDS BELOW.
# Helper variables
# shellcheck disable=SC2034
filter_config_keys="jq '. | with_entries(if .key | (contains(\"apiKey\") or contains(\"deviceApiKey\") or contains(\"pubnubSubscribeKey\") or contains(\"pubnubPublishKey\") or contains(\"mixpanelToken\") or contains(\"wifiKey\") or contains(\"files\")) then .value = \"<hidden>\" else . end)'"
# shellcheck disable=SC2034
filter_container_envs="jq 'del(.[].Config.Env)'"

# Commands
# shellcheck disable=SC2016
commands=(
	'uptime'
	'cat /etc/os-release'
	'uname -a'
	'free -h'
	'cat /proc/cpuinfo'
	'cat /proc/meminfo'
	'cat /proc/device-tree/model'
	'ps'
	'top -b -n 1'
	'tail -500 /var/log/supervisor-log/resin_supervisor_stdout.log' # legacy
	'cat /var/log/provisioning-progress.log'
	'df -h'
	'df -ih'
	'btrfs filesystem df /mnt/data-disk' # legacy
	'btrfs filesystem df /mnt/data'
	'btrfs filesystem usage /mnt/data-disk' # legacy
	'btrfs filesystem usage /mnt/data'
	'cat /mnt/data-disk/config.json | $filter_config_keys'  # legacy
	'cat /mnt/conf/config.json | $filter_config_keys' # legacy
	'cat /mnt/boot/config.json | $filter_config_keys'
	'ls -l /mnt/boot/system-connections'
	'cat /mnt/boot/config.txt' # only for rpi...
	'cat /mnt/boot/uEnv.txt' # only for uboot devices
	'cat /mnt/boot/resinOS_uEnv.txt' # ibidem
	'mount'
	'ls -l /dev'
	'date'
	'lsusb -vvv'
	'timedatectl status'
	'/sbin/ip addr'
	'curl https://www.google.co.uk'
	'curl https://pubnub.com'
	'curl https://api.resin.io/ping'
	'journalctl -n500 -a'
	'for i in /sys/class/thermal/thermal* ; do if [ -e \$i/temp ]; then echo \$i && cat \$i/temp; fi ; done'
	'dmesg'
	'cat /var/log/messages' # legacy
	'cat /etc/resolv.conf'
	'cat /proc/net/dev'
	'cat /proc/net/udp'
	'cat /proc/net/snmp'
	'find /mnt/data/resinhup/*log -mtime -30 | xargs tail -n 10 -v'
	'netstat -ntl'
	'sysctl -a'
	'curl --max-time 5 localhost:48484/ping'
	'$ENG --version'
	'ping -c 1 -W 3 google.co.uk'
	'$ENG images'
	'$ENG ps -a'
	'$ENG stats --all --no-stream'
	'systemctl status resin-supervisor'
	'journalctl -n 200 --no-pager -a -u resin-supervisor'
	'$ENG logs resin_supervisor'
	'systemctl status $ENG'
	'journalctl -n 200 --no-pager -a -u $ENG'
	'systemctl status openvpn-resin'
	'journalctl -n 200 --no-pager -a -u openvpn-resin'
	'iptables -n -L'
	'iptables -n -t nat -L'
	'$ENG exec resin_supervisor cat /etc/resolv.conf'
	'$ENG inspect \$($ENG ps --all --quiet | tr \"\\n\" \" \") | $filter_container_envs'
	'ls -lR /proc/ 2>/dev/null | grep '/data/' | grep \(deleted\)'
	'exit'
)

function each_command()
{
	local meta_command=$1
	for command in "${commands[@]}"
	do
		eval "$meta_command \"$command\""
	done
}

function announce()
{
	echo
	echo "--- $* ---"
	echo
}

# Sadly set -x outputs to stderr and with redirection the interleaving gets
# screwed up :( let's do manually for now.
function announce_run()
{
	announce "$@"
	eval "$@" 2>&1
}

function announce_version()
{
	announce "diagnose ${DIAGNOSE_VERSION}"
	announce "NOTE: not all commands are expected to succeed on all device types"
}

function get_meminfo_field()
{
	# Thankfully this works even with busybox :)
	grep "^$1:" /proc/meminfo | awk '{print $2}'
}

function btrfs_get_data()
{
	btrfs filesystem df --raw "$1" \
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

function check_write_latency()
{
    # from https://www.kernel.org/doc/Documentation/iostats.txt:
    #
    # Field  5 -- # of writes completed
    #     This is the total number of writes completed successfully.
    # Field  8 -- # of milliseconds spent writing
    #     This is the total number of milliseconds spent by all writes (as
    #     measured from __make_request() to end_that_request_last()).

    awk -v limit=${slow_disk_write} '!/(loop|ram)/{if ($11/(($8>0)?$8:1)>limit){print "DISK PARTITION WRITES SLOW: " $3": " $11/(($8>0)?$8:1) "ms / write, sample size " $8}}' /proc/diskstats
}

function check_diskspace()
{

	if ! [ -x "$(command -v btrfs)" ]; then
		# Not a resinOS 1.x device, as btrfs does not exist
		echo "DISK: BTRFS SKIP: not resinOS 1.x device"
	else
		if ! is_mounted $mountpoint; then
			echo "DISK: DANGER: BTRFS filesystem not mounted at $mountpoint!"
			return
		fi
	fi

	# Last +0 forces the field to a number, stripping the '%' on the end.
	# Tested working on busybox.
	used_percent=$(df $mountpoint | tail -n 1 | awk '{print $5+0}')
	free_percent=$((100 - used_percent))

	# First, check that df indicates low space. If not, no need to check
	# btrfs df. This is because btrfs allocates more space than is needed,
	# so df saying we're out of space doesn't mean we actually are.
	if [ "$free_percent" -gt "$low_disk_threshold" ]; then
		echo "DISK: OK (df reports ${free_percent}% free.)"
		return
	fi

	if ! [ -x "$(command -v btrfs)" ]; then
		# if btrfs command does not exists, that's all we can check
		echo "DISK: DANGER: LOW SPACE: df reports ${free_percent}%"
	else
		# resinOS 1.x device needs check of btrfs
		read -r total used <<<"$(btrfs_get_data $mountpoint "Data, single")"
		if [ -z "$total" ]; then
			read -r total used <<<"$(btrfs_get_data $mountpoint "Data+Metadata")"
		fi

		used_percent_btrfs=$((used*100/total))
		free_percent_btrfs=$((100 - used_percent_btrfs))

		if [ "$free_percent_btrfs" -lt "$low_disk_threshold" ]; then
			echo "DISK: DANGER: LOW SPACE: df reports ${free_percent}%, btrfs reports ${free_percent_btrfs}%."
		else
			echo "DISK: OK (df reports ${free_percent}% free, but btrfs reports ${free_percent_btrfs}% free.)"
		fi
	fi
}

function check_metadata()
{
	if ! [ -x "$(command -v btrfs)" ]; then
		# Not a resinOS 1.x device, as btrfs does not exists, so no metadata
		echo "METADATA: SKIP: not resinOS 1.x device"
		return
	fi
	if ! is_mounted $mountpoint; then
		echo "METADATA: SKIP: BTRFS filesystem not mounted."
		return
	fi

	read -r total used <<<"$(btrfs_get_data $mountpoint "Data+Metadata")"
	if [ -n "$total" ]; then
		echo "BTRFS MODE: MIXED"
	else
		read -r total used <<<"$(btrfs_get_data $mountpoint "Metadata, DUP")"
		echo "BTRFS MODE: DUP"
	fi

	used_percent=$((used*100/total))
	free_percent=$((100 - used_percent))

	if [ "$free_percent" -lt "$low_metadata_threshold" ]; then
		echo "METADATA: DANGER: LOW SPACE: ${free_percent}% btrfs metadata free."
	else
		echo "METADATA: OK (${free_percent}% btrfs metadata free.)"
	fi
}

function check_docker()
{
	if (pidof $ENG >/dev/null); then
		echo "DOCKER: OK (docker is running.)"
	else
		echo "DOCKER: DANGER: docker is NOT running!"
	fi
}

function check_supervisor()
{
	container_running=$($ENG ps | grep resin_supervisor)
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

	first_server=$(grep "^nameserver" /etc/resolv.conf | \
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
	check_write_latency
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
exit
