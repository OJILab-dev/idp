// The hosting modes and their host-name rules. Imports nothing else, so cloudflare.config.ts can use it.
export {
  ADMIN_WORKER_NAME,
  HOSTING_MODES,
  IDP_WORKER_NAME,
  InvalidHostingError,
  checkHostingHosts,
  parseHostingMode,
  type HostingMode,
} from "./hosting.js";
