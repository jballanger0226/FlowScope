/**
 * Turns the bare "listen EACCES: permission denied 0.0.0.0:443" Node gives into something that says what to do. Anything else is returned unchanged.
 */
export function listenHint(e: unknown, ports: (number | undefined)[]): unknown {
  const code = (e as { code?: string } | null)?.code;
  const port = (e as { port?: number } | null)?.port ?? ports.find(p => p !== undefined);
  if (code === 'EACCES' && port !== undefined && port < 1024) {
    return new Error(`Cannot open port ${port}: ports below 1024 need a privilege. The Linux service and the container image grant it (CAP_NET_BIND_SERVICE); if it was removed, grant it again, or set FLOWSCOPE_HTTPS_PORT=8443 (or another port above 1023).`);
  }
  if (code === 'EADDRINUSE' && port !== undefined) {
    return new Error(`Cannot open port ${port}: another program is already listening on it. Stop that program, or set FLOWSCOPE_HTTPS_PORT (or FLOWSCOPE_HTTP_PORT) to a free port.`);
  }
  return e;
}
