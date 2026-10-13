export type ThemePref = 'system' | 'light' | 'dark';
const KEY = 'fs_theme';

export function getTheme(): ThemePref {
  try { const v = localStorage.getItem(KEY); if (v === 'light' || v === 'dark') return v; } catch { /* storage blocked */ }
  return 'system';
}

/** Applies and remembers the choice. "system" removes the override so the OS setting decides (it is followed live by the CSS). */
export function setTheme(p: ThemePref): void {
  const el = document.documentElement;
  if (p === 'system') el.removeAttribute('data-theme'); else el.setAttribute('data-theme', p);
  try { if (p === 'system') localStorage.removeItem(KEY); else localStorage.setItem(KEY, p); } catch { /* not remembered */ }
}
