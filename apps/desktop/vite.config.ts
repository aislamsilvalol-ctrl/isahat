import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The UI talks to the local Python bridge (isahat serve). During development
// we proxy /api to the bridge so the frontend and Tauri webview use identical
// relative paths and never fight CORS.
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
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  build: {
    target: "es2022",
    outDir: "dist",
  },
});
