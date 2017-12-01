declare module 'mkdirp-promise' {
  function mkdirp(path: string): Promise<string>;
  // https://github.com/Microsoft/TypeScript/issues/5073
  namespace mkdirp {

  }
  export = mkdirp;
}
