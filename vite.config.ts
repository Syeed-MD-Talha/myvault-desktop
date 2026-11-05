import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri expects a fixed port and serves from a relative base so the bundled
// assets work from the custom protocol.
export default defineConfig({
  base: "./",
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: "127.0.0.1",
    watch: { ignored: ["**/src-tauri/**", "**/core/**", "**/target/**"] },
  },
  build: {
    target: "chrome105",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
