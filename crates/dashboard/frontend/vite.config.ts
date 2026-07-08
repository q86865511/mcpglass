import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// mcpglass dashboard — dev proxy forwards /api to the mock server (or the real
// Rust backend once it's listening on the same port).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:7411",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
