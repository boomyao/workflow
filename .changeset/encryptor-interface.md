---
"@workflow/core": patch
"@workflow/world": patch
"@workflow/cli": patch
"@workflow/web": patch
"@workflow/world-testing": patch
---

Add Encryptor interface and thread through serialization layer

Adds `Encryptor`, `EncryptionContext`, and `KeyMaterial` interfaces to `@workflow/world`. The 8 dehydrate/hydrate serialization functions now accept an `Encryptor` parameter for future encryption support. Adds `World.getEncryptorForRun()` for cross-deployment encryption key resolution (e.g., `resumeHook()` from a newer deployment). Restructures `resumeHook` to resolve the encryptor once and reuse for both metadata decryption and payload encryption.
