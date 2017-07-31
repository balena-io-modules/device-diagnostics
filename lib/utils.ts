const os = require('os');
const _ = require('lodash');
const mixpanel = require('mixpanel');
const pkgJSON = require('../package.json');
import { Issue } from './typings';
import store from './store';
import {
  MIXPANEL_TOKEN,
  IP_REGEX,
  STATS_REGEX,
  ISSUES_MAP
} from './constants';

const isLocal = (deviceId: string) => {
  return new RegExp(IP_REGEX).test(deviceId);
};

const getSSHOpts = (deviceId: string) => {
  const sshOpts = [
    '-p 22222',
    '-o StrictHostKeyChecking=no',
    '-o UserKnownHostsFile=/dev/null'
  ];

  if (isLocal(deviceId)) {
    sshOpts.unshift(`root@${deviceId}`);
  } else {
    sshOpts.unshift(`-o Hostname=${deviceId}.vpn`);
    sshOpts.unshift('resin');
  }

  return sshOpts;
};

const analytics = (deviceId: string, trackingOff: boolean) => {
  if (isLocal(deviceId) || trackingOff) {
    // don't send analytics for devices on local network
    return;
  }
  const mx = mixpanel.init(MIXPANEL_TOKEN);
  const state = store.getState();
  return mx.track('leech', {
    distinct_id: deviceId,
    issues: state.issues.map((n: Issue) => n.id),
    stats: state.stats,
    leecher: os.userInfo().username,
    leech_version: pkgJSON.version
  });
};

const parser = (data: Buffer) => {
  const statRegex = new RegExp(STATS_REGEX);
  const issues = store.getState().issues;
  const str = data.toString();
  statRegex.test(str) && store.actions.addStat(str);

  const newIssue = ISSUES_MAP.find((issue: Issue) => {
    return _.some(issue.regex, (r: string) => {
      return str.match(new RegExp(r, 'g'));
    });
  });

  if (newIssue && !issues.find(issue => issue.id === newIssue.id)) {
    store.actions.addIssue(newIssue);
  }
};

export { analytics, isLocal, parser, getSSHOpts };
