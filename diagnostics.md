# Diagnostics Descriptions
## balenaEngine specific commands
### echo === BALENA ===
#### Summary
You have arrived at the balenaEngine section of the log output.

### $ENG --version
#### Summary
This command simply gathers the balenaEngine version information.

### $ENG images
#### Summary
Show information about balenaEngine images.

### $ENG ps -a
#### Summary
Show information about containers running currently in balenaEngine.

### $ENG stats --all --no-stream
#### Summary
Display a live stream of container(s) resource usage statistics.

### $ENG system df
#### Summary
Show balenaEngine disk usage (may differ from df results).

### systemctl status $ENG
#### Summary
Get the service status of the balenaEngine from systemd.

### journalctl -n 200 --no-pager -a -u $ENG
#### Summary
Tail the balenaEngine journal and decode any messages.

### $ENG inspect \$($ENG ps --all --quiet | tr \"\\n\" \" \") | $filter_container_envs
#### Summary
Get the configuration of each container, filtering out any privileged variables.

## Hardware specific commands

### echo === HARDWARE ===
#### Summary
You have arrived at the hardware section of the log output.

### cat /proc/cpuinfo
#### Summary

### cat /proc/device-tree/model
#### Summary

### cat /proc/meminfo
#### Summary

### top -b -n 1
#### Summary
Grab a snapshot of the current usage statistics.

### cat /var/log/provisioning-progress.log
#### Summary

### df -h
#### Summary
This command lists disk space (used/available/total) [see also the `check_localdisk` check].

### df -ih
#### Summary
This command lists number of disk inodes (used/available/total).

### for i in /sys/class/thermal/thermal\* ; do if [ -e \$i/temp ]; then echo \$i && cat \$i/temp; fi ; done
#### Summary
This command lists all available temperature readings from onboard sensors. If one is abnormally hot, that may be worth
investigating further.

### free -h
#### Summary
Lists memory usage statistics (see also the `check_memory` check)

### ls -l /dev
#### Summary
Show all available files in the `/dev` virtual filesystem.

### lsusb -vvv
#### Summary
Get lots of information about any connected USB devices.

### mount
#### Summary
Show all mounted partitions and their configuration.

### uname -a
#### Summary
Show system information (kernel, hostname, build time, architecture)

## Network specific commands

### echo === NETWORK ===
#### Summary
You have arrived at the networking section of the log output.

### /sbin/ip addr
#### Summary
Show configured network interface data.

### cat /etc/resolv.conf
#### Summary
Show configured upstream DNS servers.

### cat /proc/net/dev
#### Summary

### cat /proc/net/snmp
#### Summary

### cat /proc/net/udp
#### Summary

### curl $API_ENDPOINT/ping
#### Summary
Contact the balenaCloud backend and confirm communications.

### curl https://www.google.co.uk
#### Summary
Contact a widely accessible third-party backend and confirm communications.

### ifconfig
#### Summary
Show statistics about all network interfaces on a device. Specifically, TX/RX errors/drops/overruns are useful in
debugging a flaky network.

### iptables -n -L
#### Summary

### iptables -n -t nat -L
#### Summary

### journalctl -n 200 --no-pager -a -u openvpn-resin
#### Summary
Tail the VPN log.

### ls -l /mnt/boot/system-connections
#### Summary

### netstat -ntl
#### Summary

### nmcli --version
#### Summary
Get the version of NetworkManager.

### ping -c 1 -W 3 google.co.uk
#### Summary
Ping a widely accessible third-party backend and confirm communications.

### systemctl kill -s USR1 dnsmasq
#### Summary
Force dnsmasq to dump statistics to the journal.

### systemctl status openvpn-resin
#### Summary
Get the service status of the VPN from systemd.

## BalenaOS specific commands
### echo === OS ===
#### Summary
You have arrived at the balenaOS section of the log output.

### cat /etc/os-release
#### Summary
Show balenaOS specific build information, including real device type.

### cat /mnt/boot/config.json | $filter_config_keys
#### Summary
Grab all relevant config.json fields that are not secret keys.

### cat /mnt/boot/config.txt # only for rpi...
#### Summary

### cat /mnt/boot/resinOS_uEnv.txt # only for rpi...
#### Summary

### cat /mnt/boot/uEnv.txt # only for uboot devices
#### Summary

### cat /mnt/conf/config.json | $filter_config_keys
#### Summary
(command for legacy devices)

### cat /mnt/data-disk/config.json | $filter_config_keys
#### Summary
(command for legacy devices)

### cat /var/log/messages
#### Summary
(command for legacy devices)

### cat /var/log/provisioning-progress.log
#### Summary

### dmesg
#### Summary
Get the kernel log.

### find /mnt/data/resinhup/\*log -mtime -30 | xargs tail -n 10 -v
#### Summary
Show the end of any balenaHUP logs. These logs will indicate the time and status of all balenaHUPs that have been
issued.

### journalctl --list-boots --no-pager
#### Summary
Show all boot times that have been written to the journal (more useful if persistent logging is enabled).

### journalctl -n500 -a
#### Summary
Tail the journal generally and decode any messages.

### ls -lR /proc/ 2>/dev/null | grep '/data/' | grep \(deleted\)
#### Summary

### ps
#### Summary
Show the process table.

### stat /var/lock/resinhup.lock
#### Summary
See if there's a leftover (or currently held) balenaHUP lock.

### sysctl -a
#### Summary
Show all configured sysctl parameters. This output can be useful for comparing any potentially altered sysctls from a
standard balenaOS build.

### top -b -n 1
#### Summary

## Supervisor specific commands

### echo === SUPERVISOR ===
#### Summary
You have arrived at the balena-supervisor section of the log output.

### $ENG exec resin_supervisor cat /etc/resolv.conf
#### Summary
Check if there are configured NTP servers for the supervisor container.

### $ENG logs resin_supervisor
#### Summary
Get the supervisor logs from balenaEngine.

### curl --max-time 5 localhost:48484/ping
#### Summary
Check if the supervisor API is up & responding to requests.

### journalctl -n 200 --no-pager -a -u resin-supervisor
#### Summary
Tail the supervisor journal and decode any messages.

### systemctl status resin-supervisor
#### Summary
Get the service status of the supervisor from systemd.

### tail -500 /var/log/supervisor-log/resin_supervisor_stdout.log
#### Summary
(command for legacy devices)

## Time specific commands

### echo === TIME ===
#### Summary
You have arrived at the time section of the log output.

### date
#### Summary
Get the device's configured date. If this date does not reflect the runtime from the diagnostics panel, there may be
time sync problems.

### timedatectl status
#### Summary
Get real-time clock information, as well as synchronization status of the NTP service.

### uptime
#### Summary
Get how long the device thinks it has been up. This command only carries significance from balenaOS TODO and onwards.
