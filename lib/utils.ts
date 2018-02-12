const os = require('os');
const _ = require('lodash');
const mixpanel = require('mixpanel');
const pkgJSON = require('../package.json');
import { Issue } from './typings';
import store from './store';
import { MIXPANEL_TOKEN, IP_REGEX, STATS_REGEX, ISSUES_MAP } from './constants';

const getUserName = (username: string) => {
    return username
        ? Promise.resolve(username)
        : require('resin-token')({
              dataDirectory: require('resin-settings-client').get(
                  'dataDirectory'
              )
          }).getUsername();
};

const isLocal = (deviceId: string) => {
    return new RegExp(IP_REGEX).test(deviceId);
};

const getSSHOpts = (deviceId: string, host: string, username: string) => {
    const sshOpts = [
        '-t',
        '-o LogLevel=ERROR',
        '-o StrictHostKeyChecking=no',
        '-o UserKnownHostsFile=/dev/null'
    ];

    if (isLocal(deviceId)) {
        sshOpts.push('-p 22222');
        sshOpts.push(`root@${deviceId}`);
    } else {
        sshOpts.push('-p 22');
        sshOpts.push(`${username}@${host}`);
        sshOpts.push(`host ${deviceId}`);
    }

    return sshOpts;
};

const analytics = (deviceId: string, tracking: boolean) => {
    if (isLocal(deviceId) || tracking === false) {
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

export { analytics, isLocal, parser, getSSHOpts, getUserName };
