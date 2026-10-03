# AGENTS.md

Single-file browser app: `ed25519_cryptographic_signature_service_platform.html` ("SignCore 64") — an interactive Ed25519 sign/verify demo and architecture-spec page. No build system, no package manager, no frontend framework. A separate small test kit (C client + Node mock server) lives alongside it — see Running/#-test-kit.

## Running

- Open the HTML file directly in a browser. There is no dev server or install step.
- Page loads Tailwind and Lucide from CDNs (pinned jsdelivr URLs with SRI) — needs network; offline, styling and icons break.
- Browser smoke test: sign a payload in the workbench tab, click「帶入驗證工具檢驗」, confirm「簽章驗證通過」in the verifier tab.

### Test kit

- One command: `powershell -ExecutionPolicy Bypass -File run_test.ps1` (add `-Port <n>` to avoid 8080 conflicts). Requires `node` + `gcc`/MinGW in PATH; script compiles `sign_client_test.c`, starts `mock_signature_server.js`, waits on a health-check loop, runs 4 e2e checks (pubkey query / sign 64-byte invariant / verify pass / tamper interception), stops the exact server PID it started, and propagates the client exit code — a nonzero exit means tests failed; treat CI as red.
- `run_test.bat` is the double-clickable equivalent: it pre-checks port 8080 and kills ONLY the PID listening on that port (never `taskkill /IM node.exe`).
- The mock server takes an optional port argv (`node mock_signature_server.js 9000`).

## Gotchas

- All JS is inline in the single HTML file; UI copy is Traditional Chinese (zh-TW) — keep user-facing text in zh-TW.
- Tailwind colors `brand-*` / `surface-*` are non-standard, defined in the inline `tailwind.config` in `<head>`. Change the palette there, not in a CSS file.
- Icons use `<i data-lucide="...">`; any icon added dynamically requires a follow-up `lucide.createIcons()` call (existing code does this — keep the pattern).
- Ed25519 via WebCrypto only works in modern browsers. If `subtle.generateKey({name:"Ed25519"})` fails, the fallback generates random keys, and signing falls back to a *synthetic* random 64-byte blob that will NOT verify — that's a browser-capability issue, not a code bug.
- The cURL/Node/Python/Go snippets in the page document an *intended* server design. `mock_signature_server.js` is a test double implementing that API (`/api/v1/crypto/public-key`, `/crypto/sign`, `/crypto/verify`) for the C client — it generates a throwaway key each run and has no auth/nonce/rate-limiting; it is NOT the page's backend and the page does not call it.
- Private key persistence: on load the page reads `signcore-ed25519-key.json` from browser OPFS (`navigator.storage.getDirectory()`), with a localStorage mirror (`signcore.ed25519.key`) as fallback. File missing/corrupt → generate a new pair and write the file; the「重設/重產內部固定密鑰對」and「抹除本機金鑰檔」buttons also overwrite it. v2 file format = JSON with `public_key_hex` plus an `encryption` envelope (PBKDF2-SHA256 100k + AES-256-GCM), seed never stored in plaintext; the ciphertext is AAD-bound to the public key, and unlock does a sign+verify roundtrip to validate pub/priv pairing. Legacy v1 plaintext files auto-upgrade on load; pre-AAD v2 envelopes load via a legacy decrypt fallback and are re-encrypted. Passphrase defaults to a hardcoded demo constant (`signcore-master-2026`) — a UI indicator warns while it is unchanged, and changing it re-encrypts the file. Lock = zeroize key bytes + drop CryptoKey + clear signature state (signature output is invalidated on lock; unlock also clears `lastSignatureHex`). In degraded mode (no WebCrypto Ed25519) nothing is persisted and signing stays reachable (synthetic DEGRADED path).
- Private key import/export:
  - Export: supports AES-256-GCM encrypted JSON backup (`signcore-ed25519-backup.json`, safe for offsite backup), RFC 8410 PKCS#8 PEM (`ed25519-private.key`), and raw 32-byte hex seed (`ed25519-seed.hex`). Export is gated by lock state (must be unlocked).
  - Import: supports drag-and-drop file upload or direct text paste for JSON backup (v2 encrypted or v1 legacy), RFC 8410 PKCS#8 PEM, or 64-char raw hex seed. Public key derivation uses RFC 8410 PKCS#8 ASN.1 prefix (`302e020100300506032b657004220420` + seed) to natively extract JWK coordinates in WebCrypto. Every import strictly validates key pair integrity (`validateKeyPairIntegrity` sign+verify roundtrip) before persisting to OPFS/localStorage.
- Core invariant the page enforces/displays: signatures are exactly 64 bytes (R‖S, split at hex chars 64/64), public key 32 bytes; the verifier rejects signatures not exactly 64 bytes.
