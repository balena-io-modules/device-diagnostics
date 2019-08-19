# Device-diagnostics

## Usage
The diagnostics commands are triggered remotely via the proxy server. Navigate to
`https://dashboard.balena-cloud.com/devices/{{UUID}}/diagnostics` to run and view the output.

## Hacking

### Checks
To add more checks, first define the check function and then add the function to the `checks` array in `diagnose.sh`.

### Commands
To add more commands, simply add the command  to the `commands` array in `diagnose.sh`.
