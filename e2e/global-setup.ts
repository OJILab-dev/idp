// Builds the Worker and its pages once per run, before any worker process starts the IdP.
import { buildIdp } from "./support/build.js";

export default async function globalSetup(): Promise<void> {
  await buildIdp();
}
