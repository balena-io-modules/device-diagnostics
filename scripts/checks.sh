#!/bin/bash
DIAGNOSE_VERSION=4.0.0
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
GOOD="true"
BAD="false"

# Helper functions
function announce_version()
{
	jq -n --arg dv "${DIAGNOSE_VERSION}" '{"diagnose_version":$dv}'
}

function get_meminfo_field()
{
	# Thankfully this works even with busybox :)
	grep "^$1:" /proc/meminfo | awk '{print $2}'
}

function log_status()
{
	# success (g) ${1}
	# function (f) ${2}
	# status (s) ${3}
	jq -cn --argjson g "${1}" --arg f "${2}" --arg s "${3}" '[{"name":$f,"success":$g,"status":$s}]'
}

# Check functions
function check_under_voltage(){
	if dmesg | grep -q "Under-voltage detected\!"; then
		log_status "${BAD}" "${FUNCNAME[0]}" "Under-voltage events detected, check/change the power supply ASAP"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "No under-voltage events detected"
	fi
}

function check_resin1x()
{
	# test resinOS 1.x based on matches like the following:
	# VERSION="1.24.0"
	# PRETTY_NAME="Resin OS 1.24.0"
	if grep -q -e '^VERSION="1.*$' -e '^PRETTY_NAME="Resin OS 1.*$' /etc/os-release; then
		log_status "${BAD}" "${FUNCNAME[0]}" "resinOS 1.x is now completely deprecated"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "balenaOS 2.x detected"
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
		log_status "${BAD}" "${FUNCNAME[0]}" "Low memory: ${percent}% (${avail_mb}%MB) available. ${used_mb}MB/${total_mb}MB used."
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "${percent}% memory available"
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
	local write_output
	write_output=$(awk -v limit=${slow_disk_write} '!/(loop|ram)/{if ($11/(($8>0)?$8:1)>limit){print $3": " $11/(($8>0)?$8:1) "ms / write, sample size" $8}}' /proc/diskstats)
	if [ -n "${write_output}" ]; then
		log_status "${BAD}" "${FUNCNAME[0]}" "Slow disk writes detected: ${write_output}"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "No slow disk writes detected"
	fi
}

function check_diskspace()
{

	# Last +0 forces the field to a number, stripping the '%' on the end.
	# Tested working on busybox.
	used_percent=$(df ${mountpoint} | tail -n 1 | awk '{print $5+0}')
	free_percent=$((100 - used_percent))

	if [ "${free_percent}" -lt "${low_disk_threshold}" ]; then
		log_status "${BAD}" "${FUNCNAME[0]}" "Low disk space: (df reports ${free_percent}% free.)"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "df reports ${free_percent}% free"
	fi
}

function check_container_engine()
{
	if (! pidof $ENG >/dev/null); then
		log_status "${BAD}" "${FUNCNAME[0]}" "Container engine ${ENG} is NOT running!"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "Container engine ${ENG} is running!"
	fi
}

function check_supervisor()
{
	container_running=$($ENG ps | grep resin_supervisor)
	if [ -z "$container_running" ]; then
		log_status "${BAD}" "${FUNCNAME[0]}" "Supervisor is NOT running!"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "Supervisor is running"
	fi
}

function check_dns()
{
	if [ ! -f /etc/resolv.conf ]; then
		log_status "${BAD}" "${FUNCNAME[0]}" "/etc/resolv.conf missing!"
		return
	fi

	first_server=$(grep "^nameserver" /etc/resolv.conf | \
				  head -n 1 | \
				  awk '{print $2}')

	log_status "${GOOD}" "${FUNCNAME[0]}" "First DNS server is ${first_server}"
}

function run_checks()
{
	# TODO remove echo | jq
	echo "$(check_resin1x)" \
	"$(check_under_voltage)" \
	"$(check_memory)" \
	"$(check_container_engine)" \
	"$(check_supervisor)" \
	"$(check_dns)" \
	"$(check_diskspace)" \
	"$(check_write_latency)" \
	| jq -s 'add | {checks:.}'
}

jq --argjson a1 "$(announce_version)" --argjson a2 "$(run_checks)" -cn '$a1 + $a2'
