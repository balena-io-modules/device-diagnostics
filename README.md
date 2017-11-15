# Leech

### Prerequisites

This script is pretty basic for now - ~~it assumes you have an ssh alias `resin`
hooked up to the resin management servers and all appropriate ssh keys in
place~~ - see the entry in the [scratch pad][scratch] for details on how to do
this.

This script requires an existing account on the resin environment that the
device is on. It also requires that the local ssh keys are stored in the resin
account (**This does not mean the master ssh key, the master ssh key is not
needed anymore at all**). Just use the same ssh keys you would to push to the
resin account. The resin account needs access to the device to be leeched,
either the device is owned by the account, or the accout is a support agent and
the device is open for support or the account is an admin account.

## Using

Retrieves diagnostic information from a user device.

Currently the script simply copies a diagnostic script over to
the device then runs it there, redirecting output to `out/$UUID_<TIME>.txt`,
where `<TIME>` is the localtime when leech has started.
It uses `diagnose.sh` to generate this script.

Usage is:

```bash
./leech.sh [optional: resin|resinstaging] [resin username] [device uuid]
```

The script first checks that the device with the specified vpn address matches
the provided uuid to avoid receiving data from an incorrect device (VPN
addresses get reused.)

If the first argument is not used it defaults to `resin`.

## Hacking

To add more checks, simply add commands to the `commands` array in
`diagnose.sh`.

[scratch]:https://github.com/resin-io/hq/wiki/Scratch-Pad#accessing-user-devices
