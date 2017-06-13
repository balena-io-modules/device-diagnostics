#!/bin/bash
# Script version information
VERSION=v1.0.2

# Where to save the leech error log
ERROR_LOG_FILE=${ERROR_LOG_FILE=/tmp/leech_err}

function fatal()
{
	echo $@ >&2

	if [ -f "$ERROR_LOG_FILE" ]; then
		echo -e "\nOUTPUT ($ERROR_LOG_FILE):\n"
		cat $ERROR_LOG_FILE
	fi

	exit 1
}

rm -f $ERROR_LOG_FILE

if [ -z "$1" ]; then
	fatal usage: $(basename $0) [device uuid]
fi

if [ ! -f diagnose.sh ]; then
	fatal Missing diagnose.sh file.
fi

uuid=$1

# Gets current script dir, see http://stackoverflow.com/a/246128.
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out_dir=${script_dir}/out
out_file=${uuid}_$(date +%Y%m%d%H%M).txt
output=${out_dir}/${out_file}

mkdir -p ${out_dir}

ssh_opts="-o Hostname=$uuid.vpn -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

echo Executing script...
ssh $ssh_opts resin "export LEECH_VERSION=${VERSION}; bash -s" <${script_dir}/diagnose.sh >$output 2>$ERROR_LOG_FILE
[ "$?" != 0 ] && fatal "ERROR: Script execution failed."

echo Done! Output stored in $out_file
