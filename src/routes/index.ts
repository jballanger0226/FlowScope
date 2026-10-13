import type { App } from '../app.js';
import { registerAuth } from './auth.js';
import { registerFlows } from './flows.js';
import { registerLinks } from './links.js';
import { registerReports } from './reports.js';
import { registerStorage } from './storage.js';
import { registerDevices } from './devices.js';
import { registerAdmin } from './admin.js';
import { registerSaml } from './saml.js';
import { registerSystem } from './system.js';

export function registerRoutes(app: App): void {
  registerAuth(app);
  registerSaml(app);
  registerSystem(app);
  registerFlows(app);
  registerLinks(app);
  registerReports(app);
  registerStorage(app);
  registerDevices(app);
  registerAdmin(app);
}
