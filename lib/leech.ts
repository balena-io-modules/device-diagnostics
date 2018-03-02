import * as byline from 'byline';
import { spawn } from 'child_process';
import * as dateFormat from 'dateformat';
import * as fs from 'fs';
import * as _ from 'lodash';
import * as path from 'path';
import store from './store';
import { parser, getSSHOpts } from './utils';
import { LEECH_DIR, SSH_HOST } from './constants';

export default (deviceId: string, host = SSH_HOST, username: string) => {
    return new Promise(resolve => {
        const now = new Date();
        const outputFilePath = path.join(
            LEECH_DIR,
            deviceId,
            `${dateFormat(now, 'yyyymmdd_HHMMss')}.txt`
        );

        const diagnose = fs.createReadStream(
            `${__dirname}/../scripts/diagnose.sh`
        );
        const ssh = spawn(`ssh`, getSSHOpts(deviceId, host, username));
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
            // ignore common warnings outputted from diagnose.sh
            const warningFilter = ['No such file or directory'];
            if (!_.some(warningFilter, w => _.includes(e, w))) {
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
