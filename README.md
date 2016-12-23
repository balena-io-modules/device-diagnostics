# Leech

### Prerequisites

This script is pretty basic for now - it assumes you have an ssh alias `resin`
hooked up to the resin management servers and all appropriate ssh keys in
place - see the entry in the [scratch pad][scratch] for details on how to do
this.

## Using

Retrieves diagnostic information from a user device.

Currently the script simply copies a diagnostic script over to
the device then runs it there, redirecting output to `out/$UUID.txt`. It uses
`diagnose.sh` to generate this script.

Usage is:

```bash
./leech.sh [device uuid]
```

The script first checks that the device with the specified vpn address matches
the provided uuid to avoid receiving data from an incorrect device (VPN
addresses get reused.)

## Hacking

To add more checks, simply add commands to the `commands` array in
`diagnose.sh`.

[scratch]:https://resinio.atlassian.net/wiki/pages/viewpage.action?spaceKey=RES&title=Scratch+Pad#ScratchPad-AccessingUserDevices
