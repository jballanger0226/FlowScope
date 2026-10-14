/**
 * A repeating job that never overlaps itself: if the previous run has not finished when the next tick arrives, that tick is skipped.
 * Retention and rollups can take longer than a minute on a large database, and two of them at once only slow each other down.
 * The timer does not keep the process alive.
 */
export function guardedInterval(ms: number, fn: () => void | Promise<void>, onError: (e: unknown) => void): NodeJS.Timeout {
  let running = false;
  const t = setInterval(() => {
    if (running) return;
    running = true;
    void (async () => { try { await fn(); } catch (e) { onError(e); } finally { running = false; } })();
  }, ms);
  t.unref();
  return t;
}
