# Leech

### Prerequisites

This script requires an existing account on the balenaCloud environment that the
device is on. It also requires that the local ssh keys are stored in your balena
account (**This does not mean the master ssh key, the master ssh key is not
needed anymore at all**). Just use the same ssh keys you would to push to the
balena account. The balena account needs access to the device to be leeched,
either the device is owned by the account, or the account is a support agent and
the device is open for support or the account is an admin account.

## Using

```
npm link
```

```
leech diagnose <localDeviceIP|deviceUUID>
```

![demo](output.gif)

## usage

```
Use this command to diagnose a local or remote devices

Options:
  -h: hostname, default=device.balena-devices.com (use device.balena-staging-devices.com for staging)
  -u: username used to authenticate ssh keys, default=username retrieved from local balena-token
  -t: track with mixpanel, default=true
Examples:
  $ leech diagnose 0d30096f589da97eb9236abeaee3625a
  $ leech diagnose 192.168.1.125
  $ leech diagnose -h=device.balena-staging-devices.com 0d30096f589da97eb9236abeaee3625a
  $ leech diagnose -u=unicorn 0d30096f589da97eb9236abeaee3625a
```

## Configuration

| Environment variable | Default     | Required |
|-----------------------|-------------|----------|
| LEECH_DIR             | $HOME/leech |          |

## Mapping issues

The cli, will parse the out put from commands in `diagnose.sh` line by line matching against regexes defined in `/lib/contants.ts`, Each issue must have an `id` which correlates to github issue number, a `regex` for matching logs and a `link` to some form of documentation on the bug.

## Analytics

Every leech on a remote device is reported to mixpanel.

`leech` event example:
```
{
  distinct_id: `<device_uuid>`
  issues: [
    <id>,
    <id>
  ],
  stats: [
    'MEM: OK (79% available.)',
    'DOCKER: OK (docker is running.)',
    'SUPERVISOR: OK (supervisor is running)'
    ...
  ],
  leecher: <os.userInfo().username>,
  leech_version: '1.1.6'
}
```

If the first argument is not used it defaults to `resin`.

## Hacking

To add more checks, simply add commands to the `commands` array in
`diagnose.sh`.

[scratch]:https://github.com/resin-io/hq/wiki/Scratch-Pad#accessing-user-devices
