### check_balenaOS

| Aspect         | Information                                                                                                                                                                                                                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary**    | This check confirms that the version of balenaOS is >2.x. There is further confirmation that the OS release has not since been removed from production. As of May 1, 2019, [balenaOS 1.x has been deprecated](https://www.balena.io/blog/all-good-things-come-to-an-end-including-balenaos-1-x/). |
| **Triage**     | Upgrade your device to the latest balenaOS 2.x (contact support if running 1.x).                                                                                                                                                                                                                  |
| **Depends on** | Parts of this check depend on fully functional networking stack (see [check_networking](#check_networking)).                                                                                                                                                                                      |

### check_under_voltage

| Aspect      | Information                                                                                                                                                                                                               |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary** | Often seen on Raspberry Pi devices, these kernel messages indicate that the power supply is insufficient for the device and any peripherals that might be attached. These errors also precede seemingly erratic behavior. |
| **Triage**  | Replace the power supply with a known-good supply (supplying at least 5V / >2.5A).                                                                                                                                        |

### check_memory

| Aspect                              | Information                                                                                                                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary**                         | This check simply confirms that a given device is running at a given memory threshold (set to 90% at the moment). Oversubscribed memory can lead to OOM events.             |
| **Triage**                          | Using a tool like `top`, scan the process table for which process(es) are consuming the most memory (`%VSZ`) and check                                                      |
| for memory leaks in those services. |
| **Further Reading**                 | Oversubscribed memory can lead to OOM events (learn more about the [out-of-memory killer](https://www.kernel.org/doc/html/latest/admin-guide/mm/concepts.html#oom-killer)). |

### check_container_engine

| Aspect      | Information                                                                                                                                                                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary** | This check confirms the container engine is up and healthy. Additionally, this check confirms that there have been no unclean restarts of the engine. These restarts could be caused by crashlooping. The container engine is an integral part of the balenaCloud pipeline. |
| **Triage**  | It is best to let balena's support team take a look before restarting the container engine. At the very least, take a diagnostics snapshot before restarting anything.                                                                                                      |

### check_supervisor

| Aspect      | Information                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Summary** | This check confirms the Supervisor is up and healthy. The Supervisor is an integral part of the balenaCloud pipeline. The Supervisor depends on the container engine being healthy (see [check_container_engine](#check_container_engine)). There is also a check to confirm the running Supervisor is a released version, and that the Supervisor is running the intended release from the API. |
| **Triage**  | It is best to let balena's support team take a look before restarting the supervisor. At the very least, take a diagnostics snapshot before restarting anything.                                                                                                                                                                                                                                 |

### check_localdisk

| Aspect      | Information                                                                                            |
| ----------- | ------------------------------------------------------------------------------------------------------ |
| **Summary** | This check combines a few metrics about the local storage media and reports back any potential issues. |


### test_disk_space

| Aspect              | Description                                                                                                                                                                                                                                                                                                                                                 |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary**         | Confirms device disk utilization is below a set threshold (90%). High disk usage can cause issues in supervisor and release containers.                                                                                                                                                                                                                     |
| **Triage**          | Run `du -a /mnt/data/docker                                                                                                                                                                                                                                                                                                                                 | sort -nr | head -10` in the hostOS shell to identify large files/directories for cleanup. |
| **Further Reading** | If the results indicate large files in `/mnt/data/docker/containers`, this result often indicates a leakage in a container that can be cleaned up (runaway logs, too much local data, etc). Further info can be found in the [Device Debugging Masterclass](https://www.balena.io/docs/learn/more/masterclasses/device-debugging/#111-out-of-space-issues). |

### test_write_latency

| Aspect              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary**         | Compares partition's average write latency to a target (1s), accounting for write number and size variability.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **Triage**          | Slow disk writes could indicate hardware issues or heavy disk I/O, warranting further investigation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **Further Reading** | There are some caveats to this test that are worth considering. Since it attempts to categorize a distribution with a point sample, the reported sample size should always be considered. Smaller sample sizes are prone to fluctuations that do not necessarily indicate failure. Additionally, the metric sampled is merely the number of writes disregarding the size of each write, which again may be noisy with few samples. Writes come primarily from application workloads and less often from operating system operations. For more information, see the [relevant kernel documentation](https://www.kernel.org/doc/Documentation/iostats.txt). |

### test_disk_expansion

| Aspect      | Description                                                                                                                                                                   |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary** | Ensures the host OS has expanded the partition at boot, allocating >80% of total disk space.                                                                                  |
| **Triage**  | Failure to expand root filesystem may indicate storage issues or provisioning failures. It is best to contact support, replace the storage media and re-provision the device. |

### test_data_partition_mounted

| Aspect      | Description                                                                                                                                                          |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary** | Confirms the data partition is properly mounted.                                                                                                                     |
| **Triage**  | Failure to mount the data partition can indicate an unhealthy storage medium or other problems on the device.  It is best to contact support to investigate further. |

### check_timesync
| Aspect      | Description                                                                                                          |
| ----------- | -------------------------------------------------------------------------------------------------------------------- |
| **Summary** | Verifies system clock synchronization.                                                                               |
| **Triage**  | Confirm that NTP is not blocked at the network level, and that any specified upstream NTP servers are accessible. If absolutely necessary, it is possible to temporarily sync the clock using HTTP headers (though this change will not persist across reboots). Further info can be found in the [Device Debugging Masterclass](https://www.balena.io/docs/learn/more/masterclasses/device-debugging/#61-ntp-failure). |
| **Depends on** | Depends on a fully functional networking stack (see [check_networking](#check_networking)). |

### check_temperature
| Aspect                    | Description                                              |
| ------------------------- | -------------------------------------------------------- |
| **Summary**               | Monitors for high temperature and CPU throttling signs.  |
| **test_temperature_now**  | Confirms temperature is below 80C to prevent throttling. |
| **test_throttling_dmesg** | Searches kernel logs for CPU throttling evidence.        |

### check_os_rollback
| Aspect      | Description                                                                                                                                            |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Summary** | Confirms no failed boots & rollbacks have been noted by the host OS.                                                                                   |
| **Triage**  | For detailed investigation, contact support. Read more about [Rollbacks](https://github.com/balena-os/meta-balena/blob/development/docs/rollbacks.md). |

### check_networking
| Aspect         | Description                                                                                                    |
| -------------- | -------------------------------------------------------------------------------------------------------------- |
| **Summary**    | Tests for common network failures impacting container lifecycle. Includes various network functionality tests. |
| **Depends on** | Healthy container engine (check_container_engine).                                                             |
| **Triage**     | Solutions may involve addressing local network issues or connectivity reliability.                             |

### check_user_services
| Aspect         | Description                                                                                                               |
| -------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Summary**    | Queries engine for restarts or healthcheck failures in user-defined services. Allows custom health checks via Dockerfile. |
| **Triage**     | Investigate logs for services restarting or failing healthchecks. Issues may lie in error handling or service startup.    |
| **Depends on** | Healthy container engine (check_container_engine).                                                                        |

### check_networking

This tests common network failures that impact container lifecycle and check if all [networking requirements](https://www.balena.io/docs/reference/OS/network/2.x/#network-requirements) are being met.
This health check internally involves the following tests.

| Test Name                | Description                                                                                  | Failure Indications                                                                                                           |
| ------------------------ | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **Test Upstream DNS**    | Confirms that certain FQDNs are resolvable by each of the configured upstream DNS addresses. | Only the failed upstream DNS addresses will be shown in the test results.                                                     |
| **Test WiFi**            | Confirms that if a device is using WiFi, the signal level is above a threshold.              |                                                                                                                               |
| **Test Ping**            | Confirms that packets are not dropped during an ICMP ping.                                   |                                                                                                                               |
| **Test IPv4 Stack**      | Confirms that the device can reach a public IPv4 endpoint when an IPv4 route is detected.    |                                                                                                                               |
| **Test IPv6 Stack**      | Confirms that the device can reach a public IPv6 endpoint when an IPv6 route is detected.    | If necessary, you can [disable IPv6 entirely](https://www.balena.io/docs/reference/OS/network/2.x/#disable-ipv6) on a device. |
| **Test Balena API**      | Confirms that the device can communicate with the balenaCloud API.                           | Commonly, firewalls or MiTM devices can cause SSL failures here.                                                              |
| **Test DockerHub**       | Confirms that the device can communicate with the Docker Hub.                                |                                                                                                                               |
| **Test Balena Registry** | An end-to-end check that tries to authenticate with the balenaCloud registry.                |                                                                                                                               |

The networking health check depends on the container engine being healthy (see [check_container_engine](#check_container_engine)).

### test_balena_registry

| Aspect          | Information                                                                                                                                                                |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Description** | This test is an end-to-end check that tries to authenticate with the balenaCloud registry, confirming that all other points in the networking stack are behaving properly. |
| **Depends on**  | This test depends on the container engine being healthy (see [check_container_engine](#check_container_engine)).                                                           |
| **Triage**      | Depending on what part of this check failed, there are various fixes and workarounds. Most, however, will involve a restrictive local network or an unreliable connection. |

### check_user_services

| Aspect         | Information                                                                                                                                                                                                                                                                                             |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Summary**    | Any checks with names beginning with `check_service_` come from user-defined services. These checks query the engine to see if any services are restarting uncleanly/unexpectedly.                                                                                                                      |
| **Triage**     | Investigate the logs of whichever service(s) are restarting uncleanly or failing health checks. This issue could be a bug in the error handling or start-up of the aforementioned unhealthy services. These checks are wholly limited in scope to user services and should be triaged by the developer. |
| **Depends on** | This check depends on the container engine being healthy (see [check_container_engine](#check_container_engine)).