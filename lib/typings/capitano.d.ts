declare module 'capitano' {
  interface State {
    commands: Array<Object>;
  }
  export function command(options: Object): void;
  export function run(env: Array<String>, cb: Function): void;
  export const state: State;
}
