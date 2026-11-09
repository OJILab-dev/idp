// Node has no `cloudflare:workers` module, so vitest aliases it here (vitest.config.ts). Only the base class the
// IdP Worker extends is provided: the runtime hands it ctx and env, and the entrypoint's own methods are the real ones.

/** A stand-in for the runtime's WorkerEntrypoint: it keeps ctx and env as the runtime would. */
export abstract class WorkerEntrypoint<Env = unknown> {
  protected readonly ctx: ExecutionContext;
  protected readonly env: Env;

  constructor(ctx: ExecutionContext, env: Env) {
    this.ctx = ctx;
    this.env = env;
  }
}
