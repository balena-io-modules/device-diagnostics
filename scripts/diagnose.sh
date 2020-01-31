#!/bin/bash
DIAGNOSE_VERSION=4.12.1
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

GLOBAL_TIMEOUT=10
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
	'$ENG system df'
	'$ENG volume ls'
	'systemctl status $ENG --no-pager'
	'journalctl -n 200 --no-pager -a -u $ENG'
	'$ENG inspect \$($ENG ps --all --quiet | tr \"\\n\" \" \") | $filter_container_envs'

	# HARDWARE specific commands
	'echo === HARDWARE ==='
	'cat /proc/cpuinfo'
	'cat /proc/device-tree/model'
	'cat /proc/meminfo'
	'ps'
	'top -b -n 1'
	'cat /var/log/provisioning-progress.log'
	'df -h'
	'df -ih'
	'for i in /sys/class/thermal/thermal* ; do if [ -e \$i/temp ]; then echo \$i && cat \$i/temp; fi ; done'
	'for i in /sys/class/mmc_host/mmc*/mmc* ; do if [ -e \$i/oemid ]; then echo \$i; for j in manfid oemid name hwrev fwrev; do printf \$j: && cat \$i/\$j; done; fi; done'
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
	'curl $API_ENDPOINT/ping'
	'curl https://www.google.co.uk'
	'ifconfig'
	'iptables -n -L'
	'iptables -n -t nat -L'
	'journalctl -n 200 --no-pager -a -u \"openvpn*\"'
	'ls -l /mnt/boot/system-connections'
	'netstat -ntl'
	'nmcli --version'
	'ping -c 1 -W 3 google.co.uk'
	'systemctl kill -s USR1 dnsmasq'
	'systemctl status openvpn-resin --no-pager'

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
	'dmesg -T'
	'find /mnt/data/resinhup/*log -mtime -30 | xargs tail -n 10 -v'
	'journalctl --list-boots --no-pager'
	'journalctl -n500 -a --no-pager'
	'ls -lR /proc/ 2>/dev/null | grep '/data/' | grep \(deleted\)'
	'ps'
	'stat /var/lock/resinhup.lock'
	'sysctl -a'
	'systemctl list-units --failed --no-pager'
	'top -b -n 1'

	# SUPERVISOR specific commands
	'echo === SUPERVISOR ==='
	'$ENG exec resin_supervisor cat /etc/resolv.conf'
	'$ENG logs resin_supervisor'
	'curl --max-time 5 localhost:'"${LISTEN_PORT}"'/v1/healthy'
	'journalctl -n 200 --no-pager -a -u resin-supervisor'
	'systemctl status resin-supervisor --no-pager'
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
run_commands

# Don't return a spurious error code.
exit
