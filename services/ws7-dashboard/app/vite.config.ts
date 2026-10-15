import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies /api to the running Docker stack's nginx (localhost:8080),
// so the console is developed against real data, never mocks.
export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://localhost:8080", changeOrigin: true } },
  },
  build: { outDir: "dist", assetsDir: "assets", sourcemap: false },
});
