export interface Issue {
  regex: Array<String>;
  link: string;
  id: number;
}

export interface Params {
  deviceId: string;
}

export interface Opts {
  tracking: boolean;
  username: string;
  host: string;
}

export interface Cmd {
  signature: string;
  description: string;
  isWildcard: () => boolean;
}
