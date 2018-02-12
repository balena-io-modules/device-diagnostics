import * as _ from 'lodash';
import { EventEmitter } from 'events';
import { Issue } from './typings';

const store = (() => {
    const stats: string[] = [];
    const issues: Array<Issue> = [];
    const emitter = new EventEmitter();

    return {
        actions: {
            addIssue: (issue: Issue) => {
                if (!_.includes(issues, issue)) {
                    issues.push(issue);
                    emitter.emit('addIssue', issue);
                }
                return;
            },
            addStat: (stat: string) => {
                stats.push(stat);
                emitter.emit('addStat', stat);
            },
            end: (outputFilePath: string) =>
                emitter.emit('end', outputFilePath),
            error: (error: Error) => emitter.emit('error', error)
        },
        getState: () => {
            return {
                stats,
                issues
            };
        },
        subscribe: () => {
            return emitter;
        }
    };
})();

export default store;
