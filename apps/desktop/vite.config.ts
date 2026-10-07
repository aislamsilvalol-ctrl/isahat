import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

function readBridgeToken(): string {
  // Same location the Python bridge writes (`ISAHAT_HOME` or ~/.isahat).
  // Read here so the token stays out of the frontend bundle. Do not log it.
  const env = (
    globalThis as { process?: { env?: Record<string, string | undefined> } }
  ).process?.env;
  const base = env?.ISAHAT_HOME || join(homedir(), ".isahat");
  try {
    return readFileSync(join(base, "bridge.token"), "utf8").trim();
  } catch {
    return "";
  }
}

// The UI talks to the local Python bridge (isahat serve). During development
// we proxy /api to the bridge and attach the local token. The page itself
// never sees the secret.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8741",
        changeOrigin: true,
        rewrite: (requestPath) => requestPath.replace(/^\/api/, ""),
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq) => {
            const token = readBridgeToken();
            if (token) proxyReq.setHeader("Authorization", `Bearer ${token}`);
          });
        },
      },
    },
  },
  build: {
    target: "es2022",
    outDir: "dist",
  },
});
