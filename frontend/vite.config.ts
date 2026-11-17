import react from "@vitejs/plugin-react";
import tailwind from "@tailwindcss/vite";
import { defineConfig } from "vite";

const backend = `http://127.0.0.1:${Number(process.env.PI_FIREWALL_UI_BACKEND_PORT) || 8000}`;

export default defineConfig({
  plugins: [react(), tailwind()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {charts: ["recharts"]},
      },
    },
  },
  server: {
    proxy: {
      "/api": backend,
      "/v1": backend,
    },
  },
});
