/** True only in `vite build --mode demo` (see vite.config.ts). A compile-time constant: in the normal build every
 *  `if (DEMO)` branch, the adapter and the recorded fixtures are removed from the bundle. */
export const DEMO: boolean = import.meta.env.VITE_DEMO === "1";
