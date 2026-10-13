import { get, ApiError } from './api.js';
import { session, redraw, type Status } from './state.js';

export async function refreshStatus(): Promise<void> {
  try { const s = await get<Status>('/api/status'); session.status = s; if (session.me) session.me.collect = s.collect; }
  catch (e) { if (!(e instanceof ApiError) || e.status !== 401) { /* keep the previous status */ } }
  redraw();
}
