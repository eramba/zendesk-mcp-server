import type { NextFunction, Request, RequestHandler, Response } from "express";

export const DEFAULT_HTTP_SHUTDOWN_TIMEOUT_MS = 10_000;

export class HttpOperationTracker {
  readonly signal: AbortSignal;
  readonly #active = new Set<Promise<void>>();

  constructor(signal: AbortSignal) {
    this.signal = signal;
  }

  async track<T>(operation: (signal: AbortSignal) => T | PromiseLike<T>): Promise<T> {
    if (this.signal.aborted) {
      throw new Error("HTTP runtime is shutting down");
    }

    let complete!: () => void;
    const completion = new Promise<void>((resolve) => {
      complete = resolve;
    });
    this.#active.add(completion);

    try {
      return await operation(this.signal);
    } finally {
      this.#active.delete(completion);
      complete();
    }
  }

  async drain(timeoutMs = DEFAULT_HTTP_SHUTDOWN_TIMEOUT_MS): Promise<void> {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0) {
      throw new Error("HTTP operation drain timeout must be a non-negative integer");
    }
    if (this.#active.size === 0) return;

    let timeout: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        Promise.all([...this.#active]),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(() => {
            reject(new Error("HTTP operations did not drain before shutdown deadline"));
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }
}

export function trackHttpHandler(
  operationTracker: HttpOperationTracker,
  handler: RequestHandler,
): RequestHandler {
  return function trackedHttpHandler(
    request: Request,
    response: Response,
    next: NextFunction,
  ) {
    return operationTracker.track(() => handler(request, response, next));
  };
}

type ExpressLayer = {
  handle?: RequestHandler & { stack?: ExpressLayer[] };
  route?: { stack?: ExpressLayer[] };
};

function trackLayers(
  layers: ExpressLayer[],
  operationTracker: HttpOperationTracker,
): void {
  for (const layer of layers) {
    const nestedLayers = layer.route?.stack ?? layer.handle?.stack;
    if (nestedLayers) {
      trackLayers(nestedLayers, operationTracker);
    } else if (layer.handle) {
      layer.handle = trackHttpHandler(operationTracker, layer.handle);
    }
  }
}

export function trackRouterOperations(
  router: RequestHandler,
  operationTracker: HttpOperationTracker,
): RequestHandler {
  const layers = (router as RequestHandler & { stack?: ExpressLayer[] }).stack;
  if (!layers) {
    throw new Error("HTTP router does not expose an operation stack");
  }
  trackLayers(layers, operationTracker);
  return router;
}

export function createStandaloneHttpOperationTracker(): HttpOperationTracker {
  return new HttpOperationTracker(new AbortController().signal);
}
