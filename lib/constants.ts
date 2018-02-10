const MIXPANEL_TOKEN = '6ab2b5c8726d73dcc9e21695857d2cb7';
const IP_REGEX =
    '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$';
const STATS_REGEX = '^(MEM|DOCKER|SUPERVISOR|DNS|DISK|METADATA): .*';
const LEECH_DIR = process.env.LEECH_DIR || `${process.env.HOME}/leech`;
const SSH_HOST = 'ssh.resindevice.io';

const ISSUES_MAP = [
    {
        regex: [
            'Conflict. The name "/resin_supervisor" is already in use by container'
        ],
        id: 401,
        link:
            'https://github.com/resin-io/hq/wiki/Scratch-Pad#the-name-resin_supervisor-is-already-in-use-by-container'
    },
    {
        regex: ['Error starting daemon: Error initializing network controller'],
        id: 784,
        link:
            'https://github.com/resin-io/hq/wiki/Scratch-Pad#address-already-in-use'
    },
    {
        regex: ['EAI_AGAIN'],
        id: 783,
        link: 'https://github.com/resin-io/hq/issues/783'
    },
    {
        regex: ['ApplyLayer exit status 1 unexpected EOF'],
        id: 712,
        link: 'https://github.com/resin-io/hq/wiki/Scratch-Pad#applylayer-error'
    }
];

export {
    IP_REGEX,
    STATS_REGEX,
    MIXPANEL_TOKEN,
    LEECH_DIR,
    ISSUES_MAP,
    SSH_HOST
};
