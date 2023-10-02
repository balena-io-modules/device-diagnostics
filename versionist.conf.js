'use strict';

const execSync = require('child_process').execSync;
const exec = require('child_process').exec;

const getAuthor = (commitHash) => {
  return execSync(`git show --quiet --format="%an" ${commitHash}`, {
    encoding: 'utf8'
  }).replace('\n', '');
};

const isIncrementalCommit = (changeType) => {
  return Boolean(changeType) && changeType.trim().toLowerCase() !== 'none';
};

module.exports = {
  // This setup allows the editing and parsing of footer tags to get version and type information,
  // as well as ensuring tags of the type 'v<major>.<minor>.<patch>' are used.
  // It increments in a semver compatible fashion and does not do ano NPM package info update (N/A).
  editChangelog: true,
  parseFooterTags: true,
  getGitReferenceFromVersion: 'v-prefix',
  incrementVersion: 'semver',

  // Always add the entry to the top of the Changelog, below the header.
  addEntryToChangelog: {
    preset: 'prepend',
    fromLine: 6
  },

  // Only include a commit when there is a footer tag of 'change-type'.
  // Ensures commits which do not up versions are not included.
  includeCommitWhen: (commit) => {
    return isIncrementalCommit(commit.footer['change-type']);
  },

  // Determine the type from 'change-type:' tag.
  // Should no explicit change type be made, then no changes are assumed.
  getIncrementLevelFromCommit: (commit) => {
    if (isIncrementalCommit(commit.footer['change-type'])) {
      return commit.footer['change-type'].trim().toLowerCase();
    }
  },

  // If a 'changelog-entry' tag is found, use this as the subject rather than the
  // first line of the commit.
  transformTemplateData: (data) => {
    data.commits.forEach((commit) => {
      commit.subject = commit.footer['changelog-entry'] || commit.subject;
      commit.author = getAuthor(commit.hash);
    });

    return data;
  },

  updateVersion: (cwd, version, callback) => {
    const fs = require('fs');
    const filesToUpdate = [ `${cwd}/scripts/diagnose.sh`,`${cwd}/scripts/checks.sh`, `${cwd}/diagnostics.md`];
    for (var i = 0; i < filesToUpdate.length; i++) {
        // Now update the version
        const data = fs.readFileSync(filesToUpdate[i], 'utf8')
        // Alter the DIAGNOSE_VERSION in the script
        const result = data.replace(/DIAGNOSE_VERSION=[0-9\.]*/g, `DIAGNOSE_VERSION=${version}`);
        fs.writeFileSync(filesToUpdate[i], result);
    }
  },

  template: [
    '## v{{version}} - {{moment date "Y-MM-DD"}}',
    '',
    '{{#each commits}}',
    '{{#if this.author}}',
    ' - {{capitalize this.subject}} [{{this.author}}]',
    '{{else}}',
    '* {{capitalize this.subject}}',
    '{{/if}}',
    '{{/each}}'
  ].join('\n')
};
