// Vite's "?raw" imports give a file's text. Used by tests to load recorded traces without Node APIs.
declare module "*?raw" {
  const text: string;
  export default text;
}
