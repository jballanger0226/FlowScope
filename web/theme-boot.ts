// Runs before the page paints (loaded from <head>) so the chosen theme never flashes. Keep in step with theme.ts.
(function () {
  try {
    var v = localStorage.getItem('fs_theme');
    if (v === 'light' || v === 'dark') document.documentElement.setAttribute('data-theme', v);
  } catch (e) { /* storage blocked: follow the system */ }
})();
