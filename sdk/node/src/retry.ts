export interface RetryOptions {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  jitterRatio: number;
  retryableStatusCodes: number[];
}

export interface RetryErrorLike {
  statusCode?: number;
}

export const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxAttempts: 3,
  baseDelayMs: 100,
  maxDelayMs: 2_000,
  jitterRatio: 0.2,
  retryableStatusCodes: [408, 425, 429, 500, 502, 503, 504]
};

export function resolveRetryOptions(
  options: Partial<RetryOptions> = {}
): RetryOptions {
  return {
    maxAttempts: options.maxAttempts ?? DEFAULT_RETRY_OPTIONS.maxAttempts,
    baseDelayMs: options.baseDelayMs ?? DEFAULT_RETRY_OPTIONS.baseDelayMs,
    maxDelayMs: options.maxDelayMs ?? DEFAULT_RETRY_OPTIONS.maxDelayMs,
    jitterRatio: options.jitterRatio ?? DEFAULT_RETRY_OPTIONS.jitterRatio,
    retryableStatusCodes:
      options.retryableStatusCodes ??
      DEFAULT_RETRY_OPTIONS.retryableStatusCodes.slice()
  };
}

export async function withRetry<T>(
  operation: (attempt: number) => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const retryOptions = resolveRetryOptions(options);
  let attempt = 0;
  let lastError: unknown;

  while (attempt < retryOptions.maxAttempts) {
    attempt += 1;

    try {
      return await operation(attempt);
    } catch (error) {
      lastError = error;

      if (!isRetryableError(error, retryOptions, attempt)) {
        throw error;
      }

      await sleep(calculateRetryDelay(attempt, retryOptions));
    }
  }

  throw lastError;
}

export function isRetryableError(
  error: unknown,
  options: RetryOptions,
  attempt: number
): boolean {
  if (attempt >= options.maxAttempts) {
    return false;
  }

  if (typeof error !== "object" || error === null) {
    return false;
  }

  const retryError = error as RetryErrorLike;
  if (retryError.statusCode === undefined) {
    return true;
  }

  return options.retryableStatusCodes.includes(retryError.statusCode);
}

export function calculateRetryDelay(
  attempt: number,
  options: RetryOptions
): number {
  const exponentialDelay = Math.min(
    options.baseDelayMs * 2 ** (attempt - 1),
    options.maxDelayMs
  );

  if (exponentialDelay <= 0 || options.jitterRatio <= 0) {
    return exponentialDelay;
  }

  const jitterWindow = exponentialDelay * options.jitterRatio;
  return Math.round(exponentialDelay - jitterWindow / 2 + Math.random() * jitterWindow);
}

function sleep(milliseconds: number): Promise<void> {
  if (milliseconds <= 0) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
