import * as chalk from 'chalk';
import * as _ from 'lodash';
import store from './store';
const visuals = require('resin-cli-visuals');
import {
  isLocal
} from './utils';
import {
  Issue
} from './typings';

export default (deviceId: string) => {
  let intro:string;
  if (isLocal(deviceId)) {
    intro = `Leeching device in local network at ${deviceId}`;
  } else {
    intro = `Leeching remote device ${deviceId}`;
  }

  const spinner = new visuals.Spinner(intro);
  spinner.start();

  const subscriber = store.subscribe();
  subscriber.on('addIssue', (issue: Issue) => {
    spinner.stop();
    const issues = store.getState().issues;
    if (issues.length === 1) {
      console.log(
        chalk.yellow('\nPossible issues detected: \n------------------------')
      );
    }
    console.log(`LINK: ${chalk.blue(issue.link)}`);
    spinner.start();
  });

  subscriber.on('addStat', (stat: string) => {
    spinner.stop();
    const color = _.includes(stat, 'DANGER') ? 'red' : 'green';
    console.log(chalk[color](stat));
    spinner.start();
  });

  subscriber.on('end', (outputFilePath: string) => {
    spinner.stop();
    console.log(`\nFull output written to: ${outputFilePath}`);
  });

  subscriber.on('error', (error: Error) => {
    spinner.stop();
    console.log(chalk.red(`${error.message}`));
  });
};
