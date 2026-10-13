# Verification status

Be aware of what has actually been exercised before relying on this in production.

## Run and passing
* Typecheck of server and web sources; the unit, API-integration and protocol tests (`npm test`) on Linux with Node 22.
* NetFlow v5, v9 and IPFIX decoding and the UDP collector, using packets built by `src/sim/packets.ts` (written from the protocol specifications, not captured from real routers).
* The UI in a real browser (Chromium via Playwright) against the demo network: every tab, role-gated views, certificate and authentication screens, sign-in and sign-out, and light, dark and system themes (Chromium only; Firefox and Safari were not checked).
* Storage: the same scenario suite (`test/scenarios.ts`) passes on SQLite and on ClickHouse 25.8 (a local server).
* RADIUS and LDAP/Active Directory clients against small mock servers written for the tests.
* SAML: canonicalisation and signature checks cross-verified against fixtures produced by independent code (Python `lxml` / `cryptography`).

## Written but not run
* **Windows and macOS.** Nothing here has been executed on either OS. Code avoids POSIX-only APIs, paths come from `node:path`, and `packaging/windows` and `packaging/macos` are untested. The CI workflow runs the test suite on both; treat its first run as the real check.
* **Container image.** The Dockerfile and compose file were written without a Docker daemon available. The image layout was reproduced by hand (same files, same entry point, health check returns 0), but `docker build` itself has not been run.
* **ClickHouse beyond the test server**: other versions, clusters, TLS/auth setups, and large volumes. It is labelled experimental in the UI.

## Not validated against real systems
* **TTL expired flag**: tested with built packets and demo data, on both storage backends. Not checked against real routers; devices differ in whether they export minimum TTL and in how they count ICMP errors they generate.
* **Cisco CBQoS**: OIDs and table indexing follow the CISCO-CLASS-BASED-QOS-MIB text and a simulated agent; not run against real hardware. Class names, nested policies and counter widths differ between IOS versions.
* **RADIUS / LDAP / Active Directory**: only against the mocks above, not against FreeRADIUS, OpenLDAP or a real domain controller.
* **SAML**: not tested with a real identity provider (Entra ID, Okta, ADFS, Keycloak...). The implementation is deliberately strict (see README) and may reject assertions that other products accept. Do not rely on it as your only way in; keep the break-glass administrator enabled until you have tested your IdP.
* **Performance**: no sustained load test beyond the unit tests; ingest rates for SQLite are estimates.

## Known limits
* Dependencies were vendored from source for development because the package registries were unreachable; `package.json` lists only `net-snmp` and no lock file is included, so the first `npm install` resolves current versions.
* Switching storage backends does not migrate data.
