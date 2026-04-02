import type { TrailingClient } from "./client.js";
import type { IngestReceipt, TraceEvent } from "./types.js";

export interface BatchQueueOptions {
  maxSize?: number;
  flushIntervalMs?: number;
}

interface QueueItem {
  event: TraceEvent;
  resolve: (receipt: IngestReceipt) => void;
  reject: (error: unknown) => void;
}

const DEFAULT_BATCH_QUEUE_OPTIONS: Required<BatchQueueOptions> = {
  maxSize: 50,
  flushIntervalMs: 1_000
};

export class BatchQueue {
  readonly #client: TrailingClient;
  readonly #options: Required<BatchQueueOptions>;
  #queue: QueueItem[] = [];
  #flushTimer: ReturnType<typeof setTimeout> | undefined;
  #flushInFlight: Promise<void> | null = null;
  #closed = false;

  constructor(client: TrailingClient, options: BatchQueueOptions = {}) {
    this.#client = client;
    this.#options = {
      maxSize: options.maxSize ?? DEFAULT_BATCH_QUEUE_OPTIONS.maxSize,
      flushIntervalMs:
        options.flushIntervalMs ?? DEFAULT_BATCH_QUEUE_OPTIONS.flushIntervalMs
    };
  }

  enqueue(event: TraceEvent): Promise<IngestReceipt> {
    this.#assertOpen();

    return new Promise<IngestReceipt>((resolve, reject) => {
      this.#queue.push({ event, resolve, reject });
      this.#scheduleFlush();
    });
  }

  async flush(): Promise<void> {
    while (this.#queue.length > 0 || this.#flushInFlight) {
      await this.#flushOnce();
    }
  }

  async close(): Promise<void> {
    this.#closed = true;
    this.#clearTimer();
    await this.flush();
  }

  #scheduleFlush(): void {
    if (this.#queue.length >= this.#options.maxSize) {
      void this.#flushOnce();
      return;
    }

    if (this.#flushTimer) {
      return;
    }

    this.#flushTimer = setTimeout(() => {
      this.#flushTimer = undefined;
      void this.#flushOnce();
    }, this.#options.flushIntervalMs);
  }

  async #flushOnce(): Promise<void> {
    if (this.#flushInFlight) {
      await this.#flushInFlight;
      return;
    }

    if (this.#queue.length === 0) {
      this.#clearTimer();
      return;
    }

    this.#clearTimer();

    const batch = this.#queue.splice(0, this.#options.maxSize);
    const flushPromise = this.#client
      .ingestActions(batch.map((item) => item.event))
      .then((response) => {
        if (response.action_ids.length !== batch.length) {
          throw new Error(
            `expected ${batch.length} action ids but received ${response.action_ids.length}`
          );
        }

        for (const [index, item] of batch.entries()) {
          item.resolve({ action_id: response.action_ids[index] });
        }
      })
      .catch((error: unknown) => {
        for (const item of batch) {
          item.reject(error);
        }
      })
      .finally(() => {
        if (this.#flushInFlight === flushPromise) {
          this.#flushInFlight = null;
        }

        if (this.#queue.length > 0 && !this.#closed) {
          this.#scheduleFlush();
        }
      });

    this.#flushInFlight = flushPromise;
    await flushPromise;
  }

  #clearTimer(): void {
    if (!this.#flushTimer) {
      return;
    }

    clearTimeout(this.#flushTimer);
    this.#flushTimer = undefined;
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new Error("batch queue is already closed");
    }
  }
}
