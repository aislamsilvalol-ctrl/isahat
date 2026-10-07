// Minimal Node typings for vite.config.ts. The desktop typecheck does not
// depend on @types/node.
declare module "node:fs" {
  export function readFileSync(path: string, encoding: "utf8"): string;
}

declare module "node:os" {
  export function homedir(): string;
}

declare module "node:path" {
  export function join(...paths: string[]): string;
}
