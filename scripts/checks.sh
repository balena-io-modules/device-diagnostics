#!/bin/bash
set -o pipefail

DIAGNOSE_VERSION=4.22.19
# Don't run anything before this source as it sets PATH here
# shellcheck disable=SC1091
source /etc/profile

# Newer OS versions do not set REGISTRY_ENDPOINT via
# /usr/sbin/resin-vars; that's because the information provided by
# balena cloud is meant to be the source of truth. Thus, we add the
# REGISTRY_ENDPOINT argument for this script, and will supply that
# argument in the proxy when this script is called. To avoid having
# them overwritten by older versions of resin-vars, we save the CLI
# arguments and pop them back out after sourcing resin-vars.

# Set aside arguments, come back to them later
current_args=( "$@" )
set --
# We still need to include resin-vars on legacy systems
if [ -f /usr/sbin/resin-vars ]; then
# shellcheck disable=SC1091
  source /usr/sbin/resin-vars
else
# shellcheck disable=SC1091
  source /usr/sbin/balena-config-vars
fi
# Restore arguments passed in originally
set -- "${current_args[@]}"
# shellcheck disable=SC1091
source /etc/os-release

# Determine whether we're using the older 'rce'-aliased docker or not.
# stolen directly from the proxy:
# (https://github.com/balena-io/resin-proxy/blob/master/src/common/host-scripts.ts#L28)
X=/usr/bin/
ENG=rce
[ -x $X$ENG ] || ENG=docker
[ -x $X$ENG ] || ENG=balena
[ -x $X$ENG ] || ENG=balena-engine

TIMEOUT=10
TIMEOUT_CMD="timeout --kill-after=$(( TIMEOUT * 2 )) ${TIMEOUT}"
mountpoint="/var/lib/${ENG}"

external_fqdn="0.resinio.pool.ntp.org"
IPV4_ADDRESS="1.1.1.1" # https://1.1.1.1/dns/
IPV6_ADDRESS="2606:4700:4700::6400" # https://developers.cloudflare.com/1.1.1.1/ipv6-networks
IPV4_ENDPOINT="ipv4.google.com"
IPV6_ENDPOINT="ipv6.google.com"

# workaround for self-signed certs, waiting for https://github.com/balena-os/meta-balena/issues/1398
TMPCRT=$(mktemp)
echo "${BALENA_ROOT_CA}" | base64 -d > "${TMPCRT}"
cat /etc/ssl/certs/ca-certificates.crt >> "${TMPCRT}"

low_mem_threshold=10 #%
low_disk_threshold=10 #%
wifi_threshold=40 #%, very handwavy
expansion_threshold=80 #%
slow_disk_write=1000 #ms
temperature_threshold=80000 #millidegree C

GOOD="true"
BAD="false"

mapfile -t USERVICES < <(${TIMEOUT_CMD} "${ENG}" ps --format "{{.Names}}" | awk '/(resin|balena)_supervisor/{next;}{print}' 2> /dev/null)

# Helper functions
function help()
{
	cat << EOF
Script to run checks on balenaOS devices

Options:
	-h, --help
		Display this help and exit.

	--balenaos-registry
		Upstream registry to use for host OS apps.
EOF
}

function announce_version()
{
	jq -n --arg dv "${DIAGNOSE_VERSION}" '{"diagnose_version":$dv}'
}

function get_meminfo_field()
{
	awk '/^'"$1"':/{print $2}' /proc/meminfo
}

function log_status()
{
	# success (g) ${1}
	# function (f) ${2}
	# status (s) ${3}
	jq -cn --argjson g "${1}" --arg f "${2}" --arg s "${3}" '[{"name":$f,"success":$g,"status":$s}]'
}

function test_upstream_dns()
{
	# force dnsmasq to print statistics to journal to read them back
	systemctl kill -s USR1 dnsmasq
	for i in $(journalctl _SYSTEMD_INVOCATION_ID="$(systemctl show -p InvocationID --value dnsmasq.service)" | tail -n +2 | awk '{$1=$2=$3=""; print $0}' | grep -E -o '([12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9])|(([a-f0-9:]+:+)+[a-f0-9]+)' | sort -u); do
		# shellcheck disable=SC2001
		for j in "${external_fqdn}" "$(echo "${API_ENDPOINT}" | sed -e 's@^https*://@@')"; do
			if ! nslookup "${j}" "${i}" > /dev/null 2>&1; then
				echo "${FUNCNAME[0]}: DNS lookup failed for ${j} via upstream: ${i}"
			fi
		done;
	done
}

function test_wifi()
{
	local wifi_active_interfaces
	wifi_active_interfaces=$(${TIMEOUT_CMD} nmcli --terse --fields DEVICE,TYPE,STATE device status | \
		awk -F: '/wifi:connected$/{print $1}')
	if [[ -n ${wifi_active_interfaces} ]]; then
		local -i wifi_strength
		wifi_strengths=$(${TIMEOUT_CMD} nmcli --terse --fields DEVICE,ACTIVE,SIGNAL device wifi list)
		for ifname in ${wifi_active_interfaces}; do
			wifi_strength=$(echo "${wifi_strengths}" | awk -F: '/^'"${ifname}"':yes:/{print $3}')
			if (( wifi_strength < wifi_threshold )) && (( wifi_strength > 0 )); then
				echo "${FUNCNAME[0]}: Configured wifi interface ${ifname} has a weak signal (<${wifi_threshold}%)"
			fi
		done
	fi
}

function test_ping()
{
	local -i lost_packets
	lost_packets=$(${TIMEOUT_CMD} ping -c 3 "${external_fqdn}" 2>/dev/null | awk -F, '/loss/{print $7}')
	if (( lost_packets > 0 )); then
		echo "${FUNCNAME[0]}: Packets lost while pinging ${external_fqdn}"
	fi
}

function test_balena_api()
{
	# can we reach the API?
	local api_ret
	local -i api_retval
	api_ret=$(CURL_CA_BUNDLE=${TMPCRT} ${TIMEOUT_CMD} curl -qs "${API_ENDPOINT}/ping")
	api_retval=$?
	if [[ "${api_ret}" != "OK" ]]; then
		# from man curl:
		# EXIT CODES
		# 60	 Peer certificate cannot be authenticated with known CA certificates.
		if [ "${api_retval}" -eq 60 ]; then
			echo "${FUNCNAME[0]}: There may be a firewall blocking traffic to ${API_ENDPOINT} (SSL errors)"
			return
		fi
		echo "${FUNCNAME[0]}: Could not contact ${API_ENDPOINT}"
	fi
}

function test_balena_registry()
{
	# can we authenticate with the registry? TODO: this isn't really a good check for auth, just for connectivity
	# TODO: old OSes fail because no --password-stdin, so can't use that.
	if ! ${TIMEOUT_CMD} ${ENG} login "${REGISTRY_ENDPOINT}" -u "d_${UUID}" \
		--password "${DEVICE_API_KEY}" > /dev/null 2>&1; then
		echo "${FUNCNAME[0]}: Could not communicate with ${REGISTRY_ENDPOINT} for authentication"
	fi
	${TIMEOUT_CMD} ${ENG} logout "${REGISTRY_ENDPOINT}" > /dev/null
}

function test_ipv4_stack()
{
	# Check if device expects a functioning IPv4 stack
	if ! ip -4 route get ${IPV4_ADDRESS} &>/dev/null; then
		# Don't check if IPv4 stack works since device isn't configured to use it
		return
	fi 
	# Check if we can reach an IPv4 HTTP service since device is configured to do so 
	local -i res
	res=$(CURL_CA_BUNDLE=${TMPCRT} ${TIMEOUT_CMD} curl -qs "https://${IPV4_ENDPOINT}" 1>/dev/null 2>&1; echo $?)
	if test "$res" != "0"; then
		# from man curl:
		# EXIT CODES
		# 60	 Peer certificate cannot be authenticated with known CA certificates.
		if [ "${res}" -eq 60 ]; then
			echo "${FUNCNAME[0]}: There may be a firewall blocking traffic to https://${IPV4_ENDPOINT} (SSL errors)"
			return
		fi
		echo "${FUNCNAME[0]}: Could not contact https://${IPV4_ENDPOINT}"
	fi
}

function test_ipv6_stack()
{
	# Check if device expects a functioning IPv6 stack
	if ! ip -6 route get ${IPV6_ADDRESS} &>/dev/null; then
		# Don't check if IPv6 stack works since device isn't configured to use it
		return
	fi 
	# Check if we can reach an IPv6 HTTP service since device is configured to do so 
	local -i res
	res=$(CURL_CA_BUNDLE=${TMPCRT} ${TIMEOUT_CMD} curl -qs "https://${IPV6_ENDPOINT}" 1>/dev/null 2>&1; echo $?)
	if test "$res" != "0"; then
		# from man curl:
		# EXIT CODES
		# 60	 Peer certificate cannot be authenticated with known CA certificates.
		if [ "${res}" -eq 60 ]; then
			echo "${FUNCNAME[0]}: There may be a firewall blocking traffic to https://${IPV6_ENDPOINT} (SSL errors)"
			return
		fi
		echo "${FUNCNAME[0]}: Could not contact https://${IPV6_ENDPOINT}"
	fi
}

function test_write_latency()
{
	# from https://www.kernel.org/doc/Documentation/iostats.txt:
	#
	# Field  5 -- # of writes completed
	#	  This is the total number of writes completed successfully.
	# Field  8 -- # of milliseconds spent writing
	#	  This is the total number of milliseconds spent by all writes (as
	#	  measured from __make_request() to end_that_request_last()).
	local write_output
	write_output=$(awk -v limit=${slow_disk_write} '!/(loop|ram)/{if ($11/(($8>0)?$8:1)>limit){print $3": " $11/(($8>0)?$8:1) "ms / write, sample size " $8}}' /proc/diskstats)
	if [ -n "${write_output}" ]; then
		echo "${FUNCNAME[0]}" "Slow disk writes detected: ${write_output}"
	fi
}

function test_diskspace()
{
	# Last +0 forces the field to a number, stripping the '%' on the end.
	# Tested working on busybox.
	local -i used_percent
	local -i free_percent
	used_percent=$(df ${mountpoint} | tail -n 1 | awk '{print $5+0}')
	free_percent=$(( 100 - used_percent ))

	if (( free_percent < low_disk_threshold )); then
		echo "${FUNCNAME[0]}" "Low disk space: (df reports ${free_percent}% free)"
	fi
}

function test_disk_expansion()
{
	local -i expansion_perc
	# TODO: ceil is better, but floor is supported back to jq-1.5
	expansion_perc=$(lsblk -Jb -o NAME,SIZE,MOUNTPOINT | jq -S '.blockdevices[] | select(.children[]?.mountpoint == "/mnt/boot").size as $total |
		[.children[].size | tonumber] | 100 * add / ($total | tonumber) | floor')
	if (( expansion_perc < expansion_threshold )) ; then
		echo "${FUNCNAME[0]}" "Block media device may not have fully expanded (${expansion_perc}% of available space)"
	fi
}

function test_data_partition_mounted()
{
	data_mounted=$(awk '($2 == "/mnt/data") {print $4}' /proc/mounts)
	case $data_mounted in
		*rw*) return ;;
		*ro*) echo "${FUNCNAME[0]}" "Data partition not mounted read-write" ;;
		"") echo "${FUNCNAME[0]}" "Data partition not mounted" ;;
	esac
}

function is_valid_check()
{
	local list_type="${1}"
	shift
	local found=1 i
	read -r -a args <<< "$@"
	for i in ${args[*]}
	do
		if [ "${i}" == "${SLUG}" ] ; then
			found=0
			break
		fi
	done
	if [[ "${list_type}" == "WHITELIST" ]]; then
		return "${found}"
	elif [[ "${list_type}" == "BLACKLIST" ]]; then
		return $(( 1 - found ))
	fi
}

function run_tests()
{
	local original_check
	local subject
	original_check=${1}
	subject=${original_check//check_/}
	shift;

	local tests=("$@")

	local output
	output=""
	local cmd_out
	for i in "${tests[@]}"; do
		cmd_out=$(${i})
		if [ -n "${cmd_out}" ]; then
			output+=$'\n'$(printf '%s' "${cmd_out}")
		fi
	done
	if [ "$(echo "${output}" | wc -l)" -gt 1 ]; then
		log_status "${BAD}" "${original_check}" "Some ${subject} issues detected: ${output}"
	else
		log_status "${GOOD}" "${original_check}" "No ${subject} issues detected"
	fi
}

# Check functions
function check_networking()
{
	local tests=(
		test_upstream_dns
		test_wifi
		test_ping
		test_balena_api
		test_balena_registry
		test_ipv4_stack
		test_ipv6_stack
	)
	run_tests "${FUNCNAME[0]}" "${tests[@]}"
}

function check_localdisk()
{
	local tests=(
		test_write_latency
		test_diskspace
		test_disk_expansion
		test_data_partition_mounted
	)
	run_tests "${FUNCNAME[0]}" "${tests[@]}"
}

function check_under_voltage(){
	local SLUG_WHITELIST=('raspberrypi3-64' 'raspberrypi4-64' 'raspberry-pi' 'raspberry-pi2' 'raspberrypi3' 'fincm3')
	if is_valid_check WHITELIST "${SLUG_WHITELIST[*]}"; then
		local -i UNDERVOLTAGE_COUNT
		UNDERVOLTAGE_COUNT=$(dmesg | grep -E -c "Under-?voltage detected\!")
		if (( UNDERVOLTAGE_COUNT > 0 )); then
			log_status "${BAD}" "${FUNCNAME[0]}" "${UNDERVOLTAGE_COUNT} under-voltage events detected, check/change the power supply ASAP"
		else
			log_status "${GOOD}" "${FUNCNAME[0]}" "No under-voltage events detected"
		fi
	fi
}

function check_temperature(){
	local tests=(
		test_current_temperature
		test_throttling_dmesg
	)
	run_tests "${FUNCNAME[0]}" "${tests[@]}"
}

function test_current_temperature(){
	# see https://github.com/balena-io/device-diagnostics/issues/168
	SLUG_WHITELIST=('astro-tx2' 'blackboard-tx2' 'cti-rogue-xavier' 'jetson-nano-2gb-devkit' 'jetson-nano-emmc' 'jetson-nano' 'floyd-nano' \
		'jetson-tx1' 'jetson-tx2' 'jetson-xavier-nx-devkit-emmc' 'jetson-xavier-nx-devkit' 'jetson-xavier' \
		'jn30b-nano' 'n310-tx2' 'n510-tx2' 'nru120s-xavier' 'orbitty-tx2' 'photon-nano' 'photon-xavier-nx' \
		'spacely-tx2' 'skx2' 'apollo-tx2' 'j120-tx2' 'srd3-tx2')
	local -i temp
	for i in /sys/class/thermal/thermal* ; do
		if [ -e "$i/temp" ]; then
			temp=$(cat "$i/temp")
			if (( temp >= temperature_threshold )); then
				if is_valid_check WHITELIST "${SLUG_WHITELIST[*]}" && [ -e "$i/type" ] && grep -q "PMIC-Die" "$i/type"; then
					:
					# Ignore PMIC-Die because it reports a dummy value on Jetsons: https://forums.developer.nvidia.com/t/pmic-temperature-in-tegrastats-output/75582
				else
					echo "${FUNCNAME[0]}" "Temperature above $(( temperature_threshold / 1000 ))C detected ($i)"
				fi
			fi
		fi
	done
}


function test_throttling_dmesg(){
	# see https://github.com/balena-io/device-diagnostics/issues/183
	local -i TEMP_THROTTLING_COUNT
	TEMP_THROTTLING_COUNT=$(dmesg | grep -cE 'Temperature above threshold, cpu clock throttled')
	if (( TEMP_THROTTLING_COUNT > 0 )); then
		echo "${FUNCNAME[0]}" "${TEMP_THROTTLING_COUNT} cpu throttling events detected, check CPU temperature"
	fi

}

function check_balenaOS()
{
	# test resinOS 1.x based on matches like the following:
	# VERSION="1.24.0"
	# PRETTY_NAME="Resin OS 1.24.0"

	local variant_tag=$(echo "${VARIANT:-production}" | tr "[:upper:]" "[:lower:]")

	if grep -q -e '^VERSION="1.*$' -e '^PRETTY_NAME="Resin OS 1.*$' /etc/os-release; then
		log_status "${BAD}" "${FUNCNAME[0]}" "ResinOS 1.x is now completely deprecated"
	else
		local -i versions
		versions=$(CURL_CA_BUNDLE=${TMPCRT} curl -qs --retry 3 --max-time 5 --retry-connrefused -X GET \
			-H "Content-Type: application/json" \
			-H "Authorization: Bearer ${DEVICE_API_KEY}" \
			"${API_ENDPOINT}/v6/release?\$select=id&\$expand=release_tag&\$filter=(belongs_to__application/any(a:a/is_for__device_type/any(dt:dt/slug%20eq%20'${SLUG}')%20and%20a/is_host%20eq%20true))%20and%20is_invalidated%20eq%20false%20and%20(release_tag/any(rt:(rt/tag_key%20eq%20'version')%20and%20(rt/value%20eq%20'${VERSION}')))%20and%20((release_tag/any(rt:(rt/tag_key%20eq%20'variant')%20and%20(rt/value%20eq%20'${variant_tag}')))%20or%20not(release_tag/any(rt:rt/tag_key%20eq%20'variant')))" \
			| jq -r "[.d[]] | length")
		if (( versions == 0 )); then
			log_status "${BAD}" "${FUNCNAME[0]}" "balenaOS 2.x detected, but this version is not currently available in ${API_ENDPOINT}"
		elif (( versions > 1 )); then
			log_status "${BAD}" "${FUNCNAME[0]}" "balenaOS 2.x detected, but more than one hostapp release available in ${API_ENDPOINT}"
		else
			log_status "${GOOD}" "${FUNCNAME[0]}" "Supported balenaOS 2.x detected"
		fi
	fi
}

function check_memory()
{
	local -i total_kb
	local -i avail_kb
	local avail_exists

	total_kb=$(get_meminfo_field MemTotal)
	avail_exists=$(get_meminfo_field MemAvailable)

	if [ -z "${avail_exists}" ]; then
		# For kernels that don't support MemAvailable.
		# Not as accurate, but a good approximation.
		avail_kb=$(( $(get_meminfo_field MemFree) + \
			$(get_meminfo_field Cached) + \
			$(get_meminfo_field Buffers) ))
	else
		avail_kb="${avail_exists}"
	fi

	local -i percent_avail
	percent_avail=$(( 100 * avail_kb / total_kb ))

	if (( percent_avail < low_mem_threshold )); then
		local -i total_mb
		local -i avail_mb
		total_mb=$(( total_kb / 1024 ))
		avail_mb=$(( avail_kb / 1024 ))
		local -i used_mb
		used_mb=$(( total_mb - avail_mb ))
		log_status "${BAD}" "${FUNCNAME[0]}" "Low memory: ${percent_avail}% (${avail_mb}MB) available, ${used_mb}MB/${total_mb}MB used"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "${percent_avail}% memory available"
	fi
}

function check_timesync()
{
	local is_time_synced
	is_time_synced=$(timedatectl | awk -F": " '/(System clock|NTP) synchronized:/{print $2}')
	if [[ "${is_time_synced}" != "yes" ]]; then
		log_status "${BAD}" "${FUNCNAME[0]}" "Time is not being synchronized via NTP"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "Time is synchronized"
	fi
}

function check_container_engine() {
	local tests=(
		test_container_engine_running_now
		test_container_engine_restarts
		test_container_engine_responding
		test_container_engine_migration_failed
	)
	run_tests "${FUNCNAME[0]}" "${tests[@]}"
}

function test_container_engine_running_now() {
	if (! systemctl is-active ${ENG} > /dev/null); then
		echo "${FUNCNAME[0]}" "Container engine ${ENG} is NOT running"
	fi
}

function test_container_engine_restarts() {
	local -i engine_restarts
	engine_restarts=$(systemctl show -p NRestarts ${ENG} | awk -F= '{print $2}')
	if (( engine_restarts > 0 )); then
		local start_timestamp
		start_timestamp=$(systemctl show -p ExecMainStartTimestamp ${ENG} | awk -F= '{print $2}')
		echo "${FUNCNAME[0]}" "Container engine ${ENG} has ${engine_restarts} \
restarts and may be crashlooping (most recent start time: ${start_timestamp})"
	fi
}

function test_container_engine_responding() {
	if ! ERRMSG=$(${TIMEOUT_CMD} "${ENG}" ps 2>&1); then
		echo "${FUNCNAME[0]}" "Error querying container engine: ${ERRMSG}"
	fi
}

function test_container_engine_migration_failed() {
    # needs to match the path here:
    # https://github.com/balena-os/meta-balena/blob/master/meta-balena-common/recipes-containers/balena/balena/balena.conf.storagemigration#L3
    local logpath="/mnt/state/balena-engine-storage-migration.log"
    if [ -f "${logpath}" ]; then
        echo "${FUNCNAME[0]}" "Storage migration to overlayfs failed. Check the logs at ${logpath}."
    fi
}

function check_supervisor()
{
	# TODO: grab healthcheck results here
	if [[ ! $(${TIMEOUT_CMD} ${ENG} ps --filter "name=resin_supervisor" --filter "name=balena_supervisor" -q) ]] ; then
		log_status "${BAD}" "${FUNCNAME[0]}" "Supervisor is NOT running"
	else
		if ! curl -qs --max-time 10 "localhost:${LISTEN_PORT}/v1/healthy" > /dev/null; then
			log_status "${BAD}" "${FUNCNAME[0]}" "Supervisor is running, but may be unhealthy"
		else
			log_status "${GOOD}" "${FUNCNAME[0]}" "Supervisor is running & healthy"
		fi
	fi
}

function check_os_rollback()
{
	local root="/mnt/state"
	local health_name="rollback-health-triggered"
	local altboot_name="rollback-altboot-triggered"
	local rolled_back
	for i in "${health_name}" "${altboot_name}"; do
		if [ -f "${root}/${i}" ]; then
			rolled_back="${i}"
			break
		fi
	done

	if [[ -n "${rolled_back}" ]]; then
		log_status "${BAD}" "${FUNCNAME[0]}" "OS rollback detected: ${rolled_back}"
	else
		log_status "${GOOD}" "${FUNCNAME[0]}" "No OS rollbacks detected"
	fi
}

function check_user_services()
{
	local status healthcheck_output inspect fail_streak last_code last_output pretty_name healthy
	if (( ${#USERVICES[@]} > 0 )); then
		for service in "${USERVICES[@]}"; do

			if ! inspect=$(${TIMEOUT_CMD} "${ENG}" inspect "${service}"); then
				status="User service '${service}' inspection timed out"
				log_status "${BAD}" "check_service_${service}" "${status}"
				continue
			fi

			pretty_name=$(echo -E "${inspect}" | jq -r '.[].Config.Labels."io.balena.service-name"')
			healthcheck_output=$(echo -E "${inspect}" | jq -r '.[].State.Health | select(. != null)')
			healthy=$(echo -E "${healthcheck_output}" | jq -r '.Status == "healthy"')

			if [ -n "${healthcheck_output}" ] && [ "${healthy}" = "false" ]; then
				# artificially limited to 100 chars
				last_output=$(echo -E "${healthcheck_output}" | jq -ar '.Log[-1].Output[:100]' | sed "s/\"/\'/g")
				last_code=$(echo -E "${healthcheck_output}" | jq -ar '.Log[-1].ExitCode')
				fail_streak=$(echo -E "${healthcheck_output}" | jq -r '.FailingStreak')

				status="User service '${pretty_name}' healthcheck failed, count: ${fail_streak}"
				status+=$'\n'$(printf 'exit code: %s, output: %s' "${last_code}" "${last_output}")

				log_status "${BAD}" "check_service_${pretty_name}" "${status}"
				continue
			fi

			restart_count=$(echo -E "${inspect}" | jq -r '.[].RestartCount')

			if [ "${restart_count}" -gt 0 ]; then
				status="User service '${pretty_name}' is restarting unexpectedly, count: ${restart_count}"
				log_status "${BAD}" "check_service_${pretty_name}" "${status}"
				continue
			fi

			status="User service '${pretty_name}' is running & healthy"
			log_status "${GOOD}" "check_service_${pretty_name}" "${status}"
			continue

		done
	fi
}

function run_checks()
{
	# TODO remove echo | jq
	echo -E \
	"$(check_balenaOS)" \
	"$(check_container_engine)" \
	"$(check_localdisk)" \
	"$(check_memory)" \
	"$(check_networking)" \
	"$(check_os_rollback)" \
	"$(check_supervisor)" \
	"$(check_temperature)" \
	"$(check_timesync)" \
	"$(check_under_voltage)" \
	"$(check_user_services)" \
	| jq -s 'add | {checks:.}'
}

# Parse arguments
while [[ $# -gt 0 ]]; do
	arg="$1"

	case $arg in
		-h|--help)
			help
			exit 0
			;;
		--balenaos-registry)
			if [ -z "$2" ]; then
				log ERROR "\"$1\" argument needs a value."
			fi
			REGISTRY_ENDPOINT=$2
			shift
			;;
	esac
	shift
done

jq --argjson a1 "$(announce_version)" --argjson a2 "$(run_checks)" -cn '$a1 + $a2'
rm -f "${TMPCRT}" > /dev/null 2>&1
