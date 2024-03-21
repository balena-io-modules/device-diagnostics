# Device-diagnostics

## Usage
The diagnostics commands are triggered remotely via balenaCloud. Navigate to
`https://dashboard.balena-cloud.com/devices/{{UUID}}/diagnostics` to run and view the output.  Only
[multicontainer-capable devices (balenaOS v2.12.0 or higher)](https://www.balena.io/docs/learn/develop/multicontainer/)
are fully supported and tested (see https://github.com/balena-io/device-diagnostics/issues/126 for more discussion).

## Hacking

### Checks

To add more checks, first define the check function and then add the function to the `run_checks()` function in `checks.sh`.
Checks should be fail-first, and defensive when possible. If a failing check will emit stderr, it is better to redirect
away rather than allowing it to propagate through. All numerics should be declared as such if possible.

Additionally, all checks should be documented in [diagnostics.md](diagnostics.md).

### Diagnostic commands

To add more commands, simply add the command  to the `commands` array in `diagnose.sh`. Additionally, all comands should be documented in [device-diagnostics.md](diagnostics.md#device-diagnostics).

### Supervisor Diagnostic commands

Supervisor state diagnostics are documented in [supervisor-state.md](diagnostics.md#supervisor-state).

