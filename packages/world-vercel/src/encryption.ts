import { webcrypto } from 'node:crypto';
import type {
  EncryptionContext,
  Encryptor,
  KeyMaterial,
} from '@workflow/world';

type CryptoKey = webcrypto.CryptoKey;

const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;
const KEY_BYTES = 32; // 256 bits = 32 bytes
const NONCE_LENGTH = 12; // 96 bits for GCM
const TAG_LENGTH = 128; // 128-bit auth tag
const FORMAT_PREFIX = 'encr';
const FORMAT_PREFIX_LENGTH = 4;

export interface VercelEncryptionConfig {
  /** Raw key bytes (should be 32 bytes for AES-256) */
  deploymentKey: Uint8Array;
  /** Project ID for key derivation context */
  projectId: string;
}

/**
 * Derive a per-run encryption key using HKDF.
 *
 * @param keyMaterial - Base key material
 * @param projectId - Project ID for context
 * @param runId - Run ID for per-run isolation
 * @returns Derived AES-256 key
 */
async function deriveKey(
  keyMaterial: Uint8Array,
  projectId: string,
  runId: string
): Promise<CryptoKey> {
  const baseKey = await webcrypto.subtle.importKey(
    'raw',
    keyMaterial,
    'HKDF',
    false,
    ['deriveKey']
  );

  const info = new TextEncoder().encode(`${projectId}|${runId}`);

  return webcrypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // Zero salt - key material is already random
      info,
    },
    baseKey,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Create an Encryptor implementation for Vercel deployments.
 *
 * @param config - Encryption configuration
 * @returns Encryptor implementation with encrypt, decrypt, and getKeyMaterial methods
 */
export function createEncryptor(
  config: VercelEncryptionConfig
): Required<Encryptor> {
  const { deploymentKey, projectId } = config;

  // Validate key length - must be exactly 32 bytes for AES-256
  if (deploymentKey.length !== KEY_BYTES) {
    throw new Error(
      `Invalid deployment key length: expected ${KEY_BYTES} bytes for AES-256, got ${deploymentKey.length} bytes`
    );
  }

  return {
    async encrypt(
      data: Uint8Array,
      context: EncryptionContext
    ): Promise<Uint8Array> {
      const key = await deriveKey(deploymentKey, projectId, context.runId);
      const nonce = webcrypto.getRandomValues(new Uint8Array(NONCE_LENGTH));

      const ciphertext = await webcrypto.subtle.encrypt(
        { name: ALGORITHM, iv: nonce, tagLength: TAG_LENGTH },
        key,
        data
      );

      // Format: [encr (4 bytes)][nonce (12 bytes)][ciphertext + auth tag]
      const result = new Uint8Array(
        FORMAT_PREFIX_LENGTH + NONCE_LENGTH + ciphertext.byteLength
      );
      result.set(new TextEncoder().encode(FORMAT_PREFIX), 0);
      result.set(nonce, FORMAT_PREFIX_LENGTH);
      result.set(
        new Uint8Array(ciphertext),
        FORMAT_PREFIX_LENGTH + NONCE_LENGTH
      );

      return result;
    },

    async decrypt(
      data: Uint8Array,
      context: EncryptionContext
    ): Promise<Uint8Array> {
      // Verify format prefix
      const prefix = new TextDecoder().decode(
        data.subarray(0, FORMAT_PREFIX_LENGTH)
      );
      if (prefix !== FORMAT_PREFIX) {
        throw new Error(
          `Expected '${FORMAT_PREFIX}' prefix for encrypted data, got '${prefix}'`
        );
      }

      const key = await deriveKey(deploymentKey, projectId, context.runId);
      const nonce = data.subarray(
        FORMAT_PREFIX_LENGTH,
        FORMAT_PREFIX_LENGTH + NONCE_LENGTH
      );
      const ciphertext = data.subarray(FORMAT_PREFIX_LENGTH + NONCE_LENGTH);

      const plaintext = await webcrypto.subtle.decrypt(
        { name: ALGORITHM, iv: nonce, tagLength: TAG_LENGTH },
        key,
        ciphertext
      );

      return new Uint8Array(plaintext);
    },

    async getKeyMaterial(
      _options: Record<string, unknown>
    ): Promise<KeyMaterial | null> {
      // Return the key material for external decryption (e.g., o11y tooling)
      // In production, this might fetch from a secure endpoint based on deploymentId
      return {
        key: deploymentKey,
        derivationContext: { projectId },
        algorithm: 'AES-256-GCM',
        kdf: 'HKDF-SHA256',
      };
    },
  };
}

/**
 * Create an Encryptor from environment variables.
 *
 * Requires:
 * - VERCEL_DEPLOYMENT_KEY: Base64-encoded key material (32+ bytes recommended)
 * - VERCEL_PROJECT_ID: Project ID for key derivation context
 *
 * @returns Encryptor if environment variables are set, empty object otherwise
 */
export function createEncryptorFromEnv(): Partial<Encryptor> {
  const deploymentKeyBase64 = process.env.VERCEL_DEPLOYMENT_KEY;
  const projectId = process.env.VERCEL_PROJECT_ID;

  if (!deploymentKeyBase64 || !projectId) {
    // Encryption not available - return empty object
    return {};
  }

  const deploymentKey = Uint8Array.from(
    Buffer.from(deploymentKeyBase64, 'base64')
  );

  return createEncryptor({ deploymentKey, projectId });
}
