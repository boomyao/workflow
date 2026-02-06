import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createEncryptor, createEncryptorFromEnv } from './encryption.js';

describe('createEncryptor', () => {
  const testProjectId = 'prj_test123';
  const testRunId = 'wrun_abc123';
  // 32 bytes for AES-256
  const testDeploymentKey = new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ]);

  const encryptor = createEncryptor({
    deploymentKey: testDeploymentKey,
    projectId: testProjectId,
  });

  describe('encrypt/decrypt round-trip', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const context = { runId: testRunId };

      const encrypted = await encryptor.encrypt(plaintext, context);
      const decrypted = await encryptor.decrypt(encrypted, context);

      expect(decrypted).toEqual(plaintext);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, World!');
    });

    it('should encrypt and decrypt empty data', async () => {
      const plaintext = new Uint8Array(0);
      const context = { runId: testRunId };

      const encrypted = await encryptor.encrypt(plaintext, context);
      const decrypted = await encryptor.decrypt(encrypted, context);

      expect(decrypted).toEqual(plaintext);
    });

    it('should encrypt and decrypt large data', async () => {
      // 64KB of random data (max for getRandomValues)
      const plaintext = new Uint8Array(65536);
      crypto.getRandomValues(plaintext);
      const context = { runId: testRunId };

      const encrypted = await encryptor.encrypt(plaintext, context);
      const decrypted = await encryptor.decrypt(encrypted, context);

      expect(decrypted).toEqual(plaintext);
    });

    it('should encrypt and decrypt binary data with all byte values', async () => {
      // All possible byte values 0-255
      const plaintext = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        plaintext[i] = i;
      }
      const context = { runId: testRunId };

      const encrypted = await encryptor.encrypt(plaintext, context);
      const decrypted = await encryptor.decrypt(encrypted, context);

      expect(decrypted).toEqual(plaintext);
    });
  });

  describe('encrypted data format', () => {
    it('should produce encrypted data with "encr" prefix', async () => {
      const plaintext = new TextEncoder().encode('test');
      const context = { runId: testRunId };

      const encrypted = await encryptor.encrypt(plaintext, context);

      // Check prefix is "encr"
      const prefix = new TextDecoder().decode(encrypted.subarray(0, 4));
      expect(prefix).toBe('encr');
    });

    it('should produce encrypted data with correct structure', async () => {
      const plaintext = new TextEncoder().encode('test');
      const context = { runId: testRunId };

      const encrypted = await encryptor.encrypt(plaintext, context);

      // Format: [encr (4 bytes)][nonce (12 bytes)][ciphertext + auth tag]
      // Minimum size: 4 + 12 + 16 (auth tag) = 32 bytes
      expect(encrypted.length).toBeGreaterThanOrEqual(32);

      // Ciphertext should be at least as long as plaintext + auth tag (16 bytes)
      const ciphertextLength = encrypted.length - 4 - 12;
      expect(ciphertextLength).toBeGreaterThanOrEqual(plaintext.length + 16);
    });

    it('should produce different ciphertext for same data (random nonce)', async () => {
      const plaintext = new TextEncoder().encode('test');
      const context = { runId: testRunId };

      const encrypted1 = await encryptor.encrypt(plaintext, context);
      const encrypted2 = await encryptor.encrypt(plaintext, context);

      // Encrypted data should be different due to random nonce
      expect(encrypted1).not.toEqual(encrypted2);

      // But both should decrypt to the same plaintext
      const decrypted1 = await encryptor.decrypt(encrypted1, context);
      const decrypted2 = await encryptor.decrypt(encrypted2, context);
      expect(decrypted1).toEqual(plaintext);
      expect(decrypted2).toEqual(plaintext);
    });
  });

  describe('per-run key isolation', () => {
    it('should produce different ciphertext for different runIds', async () => {
      const plaintext = new TextEncoder().encode('sensitive data');

      const encrypted1 = await encryptor.encrypt(plaintext, {
        runId: 'wrun_run1',
      });
      const encrypted2 = await encryptor.encrypt(plaintext, {
        runId: 'wrun_run2',
      });

      // Even ignoring the random nonce, the key derivation differs
      // So the auth tags will be different
      expect(encrypted1).not.toEqual(encrypted2);
    });

    it('should fail to decrypt with wrong runId', async () => {
      const plaintext = new TextEncoder().encode('sensitive data');
      const encrypted = await encryptor.encrypt(plaintext, {
        runId: 'wrun_run1',
      });

      // Try to decrypt with a different runId - should fail auth check
      await expect(
        encryptor.decrypt(encrypted, { runId: 'wrun_run2' })
      ).rejects.toThrow();
    });
  });

  describe('decrypt validation', () => {
    it('should throw on invalid prefix', async () => {
      const invalidData = new TextEncoder().encode('invalidprefix');

      await expect(
        encryptor.decrypt(invalidData, { runId: testRunId })
      ).rejects.toThrow("Expected 'encr' prefix");
    });

    it('should throw on tampered ciphertext', async () => {
      const plaintext = new TextEncoder().encode('test');
      const encrypted = await encryptor.encrypt(plaintext, {
        runId: testRunId,
      });

      // Tamper with the ciphertext (flip a bit in the middle)
      const tampered = new Uint8Array(encrypted);
      tampered[20] ^= 0xff;

      // AES-GCM should detect tampering via auth tag
      await expect(
        encryptor.decrypt(tampered, { runId: testRunId })
      ).rejects.toThrow();
    });

    it('should throw on truncated data', async () => {
      const plaintext = new TextEncoder().encode('test');
      const encrypted = await encryptor.encrypt(plaintext, {
        runId: testRunId,
      });

      // Truncate the data
      const truncated = encrypted.subarray(0, 20);

      await expect(
        encryptor.decrypt(truncated, { runId: testRunId })
      ).rejects.toThrow();
    });
  });

  describe('getKeyMaterial', () => {
    it('should return key material with correct structure', async () => {
      const keyMaterial = await encryptor.getKeyMaterial({});

      expect(keyMaterial).not.toBeNull();
      expect(keyMaterial!.key).toEqual(testDeploymentKey);
      expect(keyMaterial!.derivationContext).toEqual({
        projectId: testProjectId,
      });
      expect(keyMaterial!.algorithm).toBe('AES-256-GCM');
      expect(keyMaterial!.kdf).toBe('HKDF-SHA256');
    });
  });

  describe('different project isolation', () => {
    it('should fail to decrypt with different projectId', async () => {
      const encryptor2 = createEncryptor({
        deploymentKey: testDeploymentKey,
        projectId: 'prj_different',
      });

      const plaintext = new TextEncoder().encode('test');
      const encrypted = await encryptor.encrypt(plaintext, {
        runId: testRunId,
      });

      // Different projectId means different derived key
      await expect(
        encryptor2.decrypt(encrypted, { runId: testRunId })
      ).rejects.toThrow();
    });

    it('should fail to decrypt with different deploymentKey', async () => {
      const differentKey = new Uint8Array(32);
      crypto.getRandomValues(differentKey);

      const encryptor2 = createEncryptor({
        deploymentKey: differentKey,
        projectId: testProjectId,
      });

      const plaintext = new TextEncoder().encode('test');
      const encrypted = await encryptor.encrypt(plaintext, {
        runId: testRunId,
      });

      // Different key means decryption fails
      await expect(
        encryptor2.decrypt(encrypted, { runId: testRunId })
      ).rejects.toThrow();
    });
  });
});

describe('createEncryptorFromEnv', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should return empty object when VERCEL_DEPLOYMENT_KEY is not set', () => {
    delete process.env.VERCEL_DEPLOYMENT_KEY;
    delete process.env.VERCEL_PROJECT_ID;

    const encryptor = createEncryptorFromEnv();

    expect(encryptor.encrypt).toBeUndefined();
    expect(encryptor.decrypt).toBeUndefined();
    expect(encryptor.getKeyMaterial).toBeUndefined();
  });

  it('should return empty object when VERCEL_PROJECT_ID is not set', () => {
    // 32 bytes base64 encoded
    process.env.VERCEL_DEPLOYMENT_KEY =
      'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
    delete process.env.VERCEL_PROJECT_ID;

    const encryptor = createEncryptorFromEnv();

    expect(encryptor.encrypt).toBeUndefined();
    expect(encryptor.decrypt).toBeUndefined();
  });

  it('should return working encryptor when both env vars are set', async () => {
    // 32 bytes base64 encoded
    process.env.VERCEL_DEPLOYMENT_KEY =
      'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
    process.env.VERCEL_PROJECT_ID = 'prj_test';

    const encryptor = createEncryptorFromEnv();

    expect(encryptor.encrypt).toBeDefined();
    expect(encryptor.decrypt).toBeDefined();
    expect(encryptor.getKeyMaterial).toBeDefined();

    // Test round-trip
    const plaintext = new TextEncoder().encode('test');
    const encrypted = await encryptor.encrypt!(plaintext, {
      runId: 'wrun_123',
    });
    const decrypted = await encryptor.decrypt!(encrypted, {
      runId: 'wrun_123',
    });
    expect(decrypted).toEqual(plaintext);
  });
});
