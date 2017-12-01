import 'mocha';
import { expect } from 'chai';
import * as fs from 'fs';
import store from '../lib/store';
import { isLocal, getSSHOpts, parser } from '../lib/utils';
import * as byline from 'byline';

const LOCAL_DEVICE = '192.168.1.1';
const HOST = 'ssh.devices.resinstaging.io';
const REMOTE_DEVICE = '0d30096f589da97eb9236abeaee3625a';
const USERNAME = 'unicorn'

describe('utils', function() {
  describe('isLocal', () => {
    it('should return true for valid IP adress', () => {
  		expect(isLocal(LOCAL_DEVICE)).to.be.true;
  	});

    it('should return false for invalid IP adress', () => {
  		expect(isLocal(REMOTE_DEVICE)).to.be.false;
  	});
  });

  describe('getSSHOpts', () => {
    it('should return valid correct ssh options for local device', () => {
  		expect(getSSHOpts(LOCAL_DEVICE, HOST, USERNAME)).to.deep.equal([
        '-t',
        '-o LogLevel=ERROR',
        '-o StrictHostKeyChecking=no',
        '-o UserKnownHostsFile=/dev/null',
        '-p 22222',
        `root@${LOCAL_DEVICE}`
      ]);
  	});

    it('should return valid correct ssh options for remote device', () => {
  		expect(getSSHOpts(REMOTE_DEVICE, HOST, USERNAME)).to.deep.equal([
        '-t',
        '-o LogLevel=ERROR',
        '-o StrictHostKeyChecking=no',
        '-o UserKnownHostsFile=/dev/null',
        '-p 22',
        `${USERNAME}@${HOST}`,
        `host ${REMOTE_DEVICE}`
      ]);
  	});
  });

  describe('parser', () => {
    // TODO: Don't make these tests dependent the store
    before((done) => {
      const readStream = fs.createReadStream(`${__dirname}/exampleLeech.txt`);
      const lineStream = byline.createStream();
      readStream.pipe(lineStream);

      lineStream.on('data', (data: Buffer) => {
        parser(data);
      });

      lineStream.on('end', () => {
        done();
      })
    });

    it('should identify potential issues', () => {
      expect(store.getState().issues).to.deep.equal([
        {
          regex: ['EAI_AGAIN'],
          id: 783,
          link: 'https://github.com/resin-io/hq/issues/783'
        }
      ]);
    })

    it('should identify all stats', () => {
      expect(store.getState().stats).to.deep.equal([
        'MEM: OK (75% available.)',
        'DOCKER: OK (docker is running.)',
        'SUPERVISOR: OK (supervisor is running).',
        'DNS: OK (first DNS server is 127.0.0.2.)',
        'DISK: OK (df reports 91% free.)',
        'METADATA: SKIP: not resinOS 1.x device'
      ]);
  	});
  });
});
