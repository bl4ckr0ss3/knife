import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri drives Vite. Fix the dev port so tauri.conf.json's devUrl matches, and
// don't let Vite clear the terminal Tauri is logging to.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    target: "es2021",
    outDir: "dist",
    emptyOutDir: true,
  },
});
