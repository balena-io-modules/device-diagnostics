import * as byline from 'byline';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as _ from 'lodash'
import store from './store';
import {
  parser,
  getSSHOpts,
} from './utils';
import {
  LEECH_DIR,
} from './constants'

export default (deviceId: string) => {
  return new Promise(resolve => {
    const today = new Date();
    const outputFilePath = `${LEECH_DIR}/${deviceId}/${today.toISOString()}.txt`;

    const diagnose = fs.createReadStream(`${__dirname}/../scripts/diagnose.sh`);
    const ssh = spawn(`ssh`, getSSHOpts(deviceId));
    const lineStream = byline.createStream();
    const writeStream = fs.createWriteStream(outputFilePath);

    // pipe commands to ssh sesh
    diagnose.pipe(ssh.stdin);
    // ssh out to parser stream
    ssh.stdout.pipe(lineStream);
    // ssh out to file
    ssh.stdout.pipe(writeStream);

    // line by line regex matcher
    lineStream.on('data', (data: Buffer) => {
      parser(data);
    });

    ssh.stderr.on('data', (err: Buffer) => {
      const e = err.toString();
      // ignore common warnings outputted from script
      const warningFilter = [
        'Pseudo-terminal',
        'to the list of known hosts',
        'No such file or directory'
      ]
      if (!_.some(warningFilter, (w) => _.includes(e, w))) {
        store.actions.error(Error(e));
      }
    });

    ssh.on('exit', (code: number) => {
      if (code === 0) {
        store.actions.end(outputFilePath);
      }
      resolve();
    });
  });
};
