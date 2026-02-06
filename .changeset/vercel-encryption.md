---
"@workflow/world-vercel": patch
---

Add Vercel encryption implementation (AES-256-GCM with HKDF)

Adds `createEncryptor()` and `createEncryptorFromEnv()` to `@workflow/world-vercel`, implementing AES-256-GCM encryption with HKDF-SHA256 per-run key derivation. Wired into `createVercelWorld()` via environment variables (`VERCEL_DEPLOYMENT_KEY`, `VERCEL_PROJECT_ID`).
