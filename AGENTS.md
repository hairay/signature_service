# AGENTS.md

Single-file project: `ed25519_cryptographic_signature_service_platform.html` ("SignCore 64") — an interactive Ed25519 sign/verify demo and architecture-spec page. No build system, no package manager, no tests, no backend, not a git repo.

## Running

- Open the HTML file directly in a browser. There is no dev server, install step, or test command.
- Page loads Tailwind and Lucide from CDNs (`cdn.tailwindcss.com`, `unpkg.com/lucide`) — needs network; offline, styling and icons break.
- Smoke test: sign a payload in the workbench tab, click「帶入驗證工具檢驗」, confirm「簽章驗證通過」in the verifier tab.

## Gotchas

- All JS is inline in the single HTML file; UI copy is Traditional Chinese (zh-TW) — keep user-facing text in zh-TW.
- Tailwind colors `brand-*` / `surface-*` are non-standard, defined in the inline `tailwind.config` in `<head>`. Change the palette there, not in a CSS file.
- Icons use `<i data-lucide="...">`; any icon added dynamically requires a follow-up `lucide.createIcons()` call (existing code does this — keep the pattern).
- Ed25519 via WebCrypto only works in modern browsers. If `subtle.generateKey({name:"Ed25519"})` fails, the fallback generates random keys, and signing falls back to a *synthetic* random 64-byte blob that will NOT verify — that's a browser-capability issue, not a code bug.
- The documented API (e.g. `POST /api/v1/crypto/sign`) and cURL/Node/Python/Go snippets describe an *intended server design*; none of it exists as code here. Don't look for a backend.
- Core invariant the page enforces/displays: signatures are exactly 64 bytes (R‖S, split at hex chars 64/64), public key 32 bytes; the verifier rejects signatures not exactly 64 bytes.
