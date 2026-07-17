import type { Server } from "node:http";

import { attachHttpListener, type HttpRuntime } from "./http-runtime.js";

const SHUTDOWN_GRACE_MS = 10_000;

type ClosableHttpListener = Pick<Server, "close" | "closeAllConnections">;
type ManagedHttpListener = ClosableHttpListener & Pick<Server, "on">;

type ProcessControl = {
  exitCode: number | undefined;
  once(signal: NodeJS.Signals, listener: () => void): unknown;
};

export type CloseHttpListenerOptions = {
  graceMs?: number;
  onGraceExpired?: () => void;
};

export type HttpLifecycleOptions = {
  process?: ProcessControl;
  logError?: (...values: unknown[]) => void;
};

export function closeHttpListener(
  listener: ClosableHttpListener,
  options: CloseHttpListenerOptions = {},
): Promise<void> {
  const graceMs = options.graceMs ?? SHUTDOWN_GRACE_MS;
  if (!Number.isSafeInteger(graceMs) || graceMs < 0) {
    throw new Error("HTTP shutdown grace period must be a non-negative integer");
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(() => {
      options.onGraceExpired?.();
      listener.closeAllConnections();
    }, graceMs);
    timer.unref();

    listener.close((error) => finish(error ?? undefined));
  });
}

export function startHttpLifecycle(
  runtime: HttpRuntime,
  listener: ManagedHttpListener,
  options: HttpLifecycleOptions = {},
): void {
  const processControl = options.process ?? process;
  const logError = options.logError ?? console.error;

  attachHttpListener(runtime, () => closeHttpListener(listener, {
    onGraceExpired() {
      logError("HTTP shutdown grace period expired");
      processControl.exitCode = 1;
    },
  }));

  let shutdownStarted = false;
  const shutdown = (signal: NodeJS.Signals, listenerError?: Error) => {
    if (listenerError) {
      logError("HTTP listener error:", listenerError.message);
      processControl.exitCode = 1;
    }
    if (shutdownStarted) return;
    shutdownStarted = true;
    if (!listenerError) {
      logError(`Received ${signal}; stopping HTTP listener`);
    }
    void runtime.shutdown(signal).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : "Unknown error";
      logError("HTTP shutdown error:", message);
      processControl.exitCode = 1;
    });
  };

  listener.on("error", (error) => shutdown("SIGTERM", error));
  processControl.once("SIGINT", () => shutdown("SIGINT"));
  processControl.once("SIGTERM", () => shutdown("SIGTERM"));
  runtime.startWorker();
}
