export interface Issue {
  regex: Array<String>;
  link: string;
  id: number;
}

export interface Params {
  deviceId: string;
}

export interface Opts {
  trackingOff: boolean;
}

export interface Cmd {
  signature: string;
  description: string;
  isWildcard: () => boolean;
}
