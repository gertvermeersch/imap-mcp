/**
 * Fixed-window failure counter, used to throttle operator sign-in attempts.
 *
 * In memory, like the pending authorization requests it protects: a restart
 * clears it, which is the right trade for a single-container server with one
 * operator. The window is fixed rather than sliding, so a persistent attacker
 * cannot extend their own lockout indefinitely — and neither can they starve
 * the real operator for longer than `windowMs`.
 */
export class FailureThrottle {
  private readonly buckets = new Map<string, { failures: number; resetAt: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number
  ) {
    setInterval(() => this.sweep(), 60_000).unref();
  }

  /** Seconds the caller must wait before trying again; 0 means go ahead. */
  retryAfter(key: string, now: number = Date.now()): number {
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now || bucket.failures < this.max) return 0;
    return Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
  }

  recordFailure(key: string, now: number = Date.now()): void {
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(key, { failures: 1, resetAt: now + this.windowMs });
      return;
    }
    bucket.failures += 1;
  }

  /** Called after a successful login so one bad guess does not linger. */
  clear(key: string): void {
    this.buckets.delete(key);
  }

  private sweep(now: number = Date.now()): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) this.buckets.delete(key);
    }
  }
}
