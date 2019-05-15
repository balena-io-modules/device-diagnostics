#!/bin/bash
DIAGNOSE_VERSION=3.0.0
# Don't run anything before this source as it sets PATH here
# shellcheck disable=SC1091
source /etc/profile
# shellcheck disable=SC1091
source /usr/sbin/resin-vars

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

slow_disk_write=1000 #ms
GLOBAL_TIMEOUT=60
GLOBAL_TIMEOUT_CMD="timeout --preserve-status --kill-after=$(( GLOBAL_TIMEOUT * 2 ))"
TIMEOUT_VERBOSE="timeout -v 1"
# timeout (GNU coreutils) 8.26 does not support -v
if "${TIMEOUT_VERBOSE}" echo > /dev/null ; then
        GLOBAL_TIMEOUT_CMD="${GLOBAL_TIMEOUT_CMD} -v"
fi
GLOBAL_TIMEOUT_CMD="${GLOBAL_TIMEOUT_CMD} ${GLOBAL_TIMEOUT}"
# resinOS v1 busybox does not support `time -o`
if [ -e "/usr/bin/time" ] ; then
	TIME_CMD="/usr/bin/time -o /dev/stdout"
	# resinOS v1 busybox does not support `time -o`
	if ! ${TIME_CMD} echo ; then
		TIME_CMD="/usr/bin/time"
	fi
else
	# if for some reason the binary does not exist, use the shell builtin
	TIME_CMD="time"
fi

# force UTC & RFC-3339 formatting
# using nanos to help with event ordering, even if not provided by NTP
DATE_CMD="date --utc --rfc-3339=ns"

GLOBAL_CMD_PREFIX="${DATE_CMD} ; ${TIME_CMD} ${GLOBAL_TIMEOUT_CMD} bash -c"

## DIAGNOSTIC COMMANDS BELOW.
# Helper variables
# shellcheck disable=SC2034
filter_config_keys='jq ". | with_entries(if .key | (contains(\"apiKey\") or contains(\"deviceApiKey\") or contains(\"pubnubSubscribeKey\") or contains(\"pubnubPublishKey\") or contains(\"mixpanelToken\") or contains(\"wifiKey\") or contains(\"files\")) then .value = \"<hidden>\" else . end)"'
# shellcheck disable=SC2034
filter_container_envs='jq "del(.[].Config.Env)"'

# Commands
# shellcheck disable=SC2016
commands=(
	# BALENA specific commands
	'echo === BALENA ==='
	'$ENG --version'
	'$ENG images'
	'$ENG ps -a'
	'$ENG stats --all --no-stream'
	'systemctl status $ENG'
	'journalctl -n 200 --no-pager -a -u $ENG'
	'$ENG inspect \$($ENG ps --all --quiet | tr \"\\n\" \" \") | $filter_container_envs'

	# HARDWARE specific commands
	'echo === HARDWARE ==='
	'cat /proc/cpuinfo'
	'cat /proc/device-tree/model'
	'cat /proc/meminfo'
	'ps'
	'top -b -n 1'
	'tail -500 /var/log/supervisor-log/resin_supervisor_stdout.log' # legacy
	'cat /var/log/provisioning-progress.log'
	'df -h'
	'df -ih'
	'for i in /sys/class/thermal/thermal* ; do if [ -e \$i/temp ]; then echo \$i && cat \$i/temp; fi ; done'
	'free -h'
	'ls -l /dev'
	'lsusb -vvv'
	'mount'
	'uname -a'

	# NETWORK specific commands
	'echo === NETWORK ==='
	'/sbin/ip addr'
	'cat /etc/resolv.conf'
	'cat /proc/net/dev'
	'cat /proc/net/snmp'
	'cat /proc/net/udp'
	'curl $API_ENDPOINT'
	'curl https://pubnub.com'
	'curl https://www.google.co.uk'
	'ifconfig'
	'iptables -n -L'
	'iptables -n -t nat -L'
	'journalctl -n 200 --no-pager -a -u openvpn-resin'
	'ls -l /mnt/boot/system-connections'
	'netstat -ntl'
	'ping -c 1 -W 3 google.co.uk'
	'systemctl kill -s USR1 dnsmasq'
	'systemctl status openvpn-resin'

	# OS specific commands
	'echo === OS ==='
	'cat /etc/os-release'
	'cat /mnt/boot/config.json | $filter_config_keys'
	'cat /mnt/boot/config.txt' # only for rpi...
	'cat /mnt/boot/resinOS_uEnv.txt' # ibidem
	'cat /mnt/boot/uEnv.txt' # only for uboot devices
	'cat /mnt/conf/config.json | $filter_config_keys' # legacy
	'cat /mnt/data-disk/config.json | $filter_config_keys'  # legacy
	'cat /var/log/messages' # legacy
	'cat /var/log/provisioning-progress.log'
	'dmesg'
	'find /mnt/data/resinhup/*log -mtime -30 | xargs tail -n 10 -v'
	'journalctl --list-boots --no-pager'
	'journalctl -n500 -a'
	'ls -lR /proc/ 2>/dev/null | grep '/data/' | grep \(deleted\)'
	'ps'
	'stat /var/lock/resinhup.lock'
	'sysctl -a'
	'top -b -n 1'

	# SUPERVISOR specific commands
	'echo === SUPERVISOR ==='
	'$ENG exec resin_supervisor cat /etc/resolv.conf'
	'$ENG logs resin_supervisor'
	'curl --max-time 5 localhost:48484/ping'
	'journalctl -n 200 --no-pager -a -u resin-supervisor'
	'systemctl status resin-supervisor'
	'tail -500 /var/log/supervisor-log/resin_supervisor_stdout.log' # legacy

	# TIME specific commands
	'echo === TIME ==='
	'date'
	'timedatectl status'
	'uptime'
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
	echo | tee /dev/stderr
	echo "--- $* ---" | tee /dev/stderr
	echo | tee /dev/stderr
}

# Sadly set -x outputs to stderr and with redirection the interleaving gets
# screwed up :( let's do manually for now.
function announce_run()
{
	announce "$@"
	eval "${GLOBAL_CMD_PREFIX} '$*'"
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

function is_mounted()
{
	# busybox grep doesn't like long options.
	mount | grep -q "on $1"
}

function check_resin1x()
{
	# test resinOS 1.x based on matches like the following:
	# VERSION="1.24.0"
	# PRETTY_NAME="Resin OS 1.24.0"
	if grep -q -e '^VERSION="1.*$' -e '^PRETTY_NAME="Resin OS 1.*$' /etc/os-release; then
		echo "WARNING: resinOS 1.x is now completely deprecated"
	fi
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

	# Last +0 forces the field to a number, stripping the '%' on the end.
	# Tested working on busybox.
	used_percent=$(df $mountpoint | tail -n 1 | awk '{print $5+0}')
	free_percent=$((100 - used_percent))

	if [ "$free_percent" -gt "$low_disk_threshold" ]; then
		echo "DISK: OK (df reports ${free_percent}% free.)"
		return
	fi

	echo "DISK: DANGER: LOW SPACE: df reports ${free_percent}%"
}

function check_container_engine()
{
	if (pidof $ENG >/dev/null); then
		echo "CONTAINER ENGINE: OK: container engine $ENG is running!"
	else
		echo "CONTAINER ENGINE: DANGER: container engine $ENG is NOT running!"
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

	check_resin1x
	check_memory
	check_container_engine
	check_supervisor
	check_dns
	check_diskspace
	check_write_latency
	check_metadata
}

function run_commands()
{
	announce COMMANDS
	announce "prefixing commands with '${GLOBAL_CMD_PREFIX}'"
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
