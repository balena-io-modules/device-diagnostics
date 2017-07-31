#!/usr/bin/env node
import * as capitano from 'capitano';
import * as mkdirp from 'mkdirp-promise';
import { LEECH_DIR } from './constants';
import { analytics } from './utils';
import { Cmd, Params, Opts } from './typings';
import logger from './logger';
import leech from './leech';
const pkgJSON = require('../package.json');
import store from './store';
process.env.LEECH_VERSION = pkgJSON.version;

const help = () => {
  console.log(`Usage: leech [COMMANDS] [OPTIONS]`);
  console.log('\nCommands:\n');
  capitano.state.commands.forEach((cmd: Cmd) => {
    if (!cmd.isWildcard()) {
      console.log(`\t${cmd.signature}\t\t\t${cmd.description}`);
    }
  });
}

capitano.command({
  signature: 'version',
  description: 'Output version information',
  action: () => console.log(pkgJSON.version)
});

capitano.command({
  signature: 'help',
  description: 'Output general help page',
  action: help
});

capitano.command({
  signature: 'diagnose <deviceId>',
  description: 'Leech device by uuid|local IP',
  options: [
    {
      signature: 'tracking-off',
      boolean: true,
      require: false,
      alias: ['t']
    }
  ],
  help: `
		Use this command to diagnose a local or remote device
		Examples:
			$ leech diagnose 0d30096f589da97eb9236abeaee3625a
      $ leech diagnose 192.168.1.125
	`,
  action: async (params: Params, opts: Opts) => {
    logger(params.deviceId);
    try {
      await mkdirp(`${LEECH_DIR}/${params.deviceId}`);
      await leech(params.deviceId);
      analytics(params.deviceId, opts.trackingOff);
    } catch (err) {
      store.actions.error(err);
      process.exit(1);
    }
  }
});

capitano.command({
  signature: '*',
	action: help
})

capitano.run(process.argv, (error: Error) => {
  if (error != null) {
    throw error;
  }
});
