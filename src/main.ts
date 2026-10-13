import { App } from './app.js';
import type { AppConfig } from './config.js';

/** Starts the application and keeps it running until a stop signal arrives. */
export async function run(cfg: AppConfig): Promise<App> {
  const app = await App.create(cfg);
  app.demo = cfg.demo;
  await app.start();
  if (cfg.demo) {
    const { startDemo } = await import('./demo.js');
    await startDemo(app);
  }

  const urls: string[] = [];
  if (app.ports.https) urls.push(`https://localhost:${app.ports.https}/`);
  if (app.ports.http) urls.push(`http://localhost:${app.ports.http}/`);
  const line = '─'.repeat(64);
  console.log(`\n${line}\n FlowScope is running${cfg.demo ? ' in DEMO mode (simulated network)' : ''}\n Web:         ${urls.join('   ')}\n Flow ports:  UDP ${app.collector.boundPorts.join(', ') || '(none open)'}\n Data folder: ${cfg.dataDir}`);
  if (app.initialAdminPassword) console.log(` First sign-in: user "admin", password "${app.initialAdminPassword}" (you must change it)`);
  console.log(`${line}\n`);

  let stopping = false;
  const stop = async (sig: string) => {
    if (stopping) return;
    stopping = true;
    console.log(`\nReceived ${sig}, shutting down...`);
    const t = setTimeout(() => { console.error('Shutdown is taking too long; exiting.'); process.exit(1); }, 15_000);
    t.unref();
    try { await app.stop(); } catch (e) { console.error('Error while stopping:', e); }
    process.exit(0);
  };
  for (const s of ['SIGINT', 'SIGTERM', 'SIGBREAK'] as const) process.on(s, () => void stop(s));
  process.on('unhandledRejection', e => { try { app.log.error('app', 'Unhandled error: ' + String((e as Error)?.stack || e)); } catch { console.error(e); } });
  return app;
}
