import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies /api to the running Docker stack's nginx (localhost:8080),
// so the console is developed against real data, never mocks.
//
// `npm run build:demo` (vite build --mode demo) builds the same console for static hosting: every API call is
// answered by src/demo/adapter.ts from a recording of a lab run (src/demo/fixtures.json). The normal build contains
// none of it.
export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    {
      name: "demo-html",
      transformIndexHtml: (html) => (mode === "demo"
        ? html.replace('<script src="/api/config.js"></script>\n', "").replace("<title>FENGARDE</title>", "<title>FENGARDE console demo</title>")
        : html),
    },
  ],
  base: "./",
  define: { "import.meta.env.VITE_DEMO": JSON.stringify(mode === "demo" ? "1" : "") },
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://localhost:8080", changeOrigin: true } },
  },
  // assetsInlineLimit 0: nginx's CSP has no `font-src data:`, so small fonts must stay real files.
  build: { outDir: "dist", assetsDir: "assets", sourcemap: false, assetsInlineLimit: 0 },
}));
