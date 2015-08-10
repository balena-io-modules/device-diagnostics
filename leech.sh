#!/bin/bash

function fatal()
{
	echo $@ >&2
	exit 1
}

if [ -z "$1" ] || [ -z "$2" ]; then
    fatal usage: $(basename $0) [vpn ip address] [device uuid]
fi

if [ ! -f diagnose_template.sh ]; then
    fatal Missing diagnose_template.sh file.
fi

ip=$1
uuid=$2

# Gets current script dir, see http://stackoverflow.com/a/246128.
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out_dir=${script_dir}/out
out_file=${uuid}.txt
output=${out_dir}/${out_file}

mkdir -p ${out_dir}
rm -rf /tmp/leech
mkdir /tmp/leech

sed "s/@@replaceme@@/$uuid/" ${script_dir}/diagnose_template.sh > /tmp/leech/diagnose.sh

# This message is apparently unavoidable when ssh is relayed :(
ignore_line="Killed by signal 1."

echo Copying script to device...
scp -q -p -o Hostname=$ip /tmp/leech/diagnose.sh resin:/home/root/ 2>&1 | grep -v "$ignore_line"
echo Executing script...
ssh -o Hostname=$ip -o UserKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=no resin "bash /home/root/diagnose.sh" 2>&1 | \
    grep -v "$ignore_line" >$output
echo Done! Output stored in $out_file
