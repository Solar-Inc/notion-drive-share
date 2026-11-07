export const CHUNK_SIZE = 4 * 1024 * 1024;
export const MAX_CHUNKS = 10000;
export const PBKDF2_ITERATIONS = 600000;

const enc = new TextEncoder();
const dec = new TextDecoder();

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function toBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 32768)
    binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value))
    throw new Error("加密資料格式無效");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function sha256Hex(value) {
  const bytes = typeof value === "string" ? enc.encode(value) : value;
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function passwordKey(password, salt, usages) {
  if (typeof password !== "string" || password.length < 12 || password.length > 256)
    throw new Error("分享密碼至少需要 12 個字元");
  const source = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS }, source,
    { name: "AES-GCM", length: 256 }, false, usages);
}

export async function wrapContentKey(contentKey, password, shareId, recipientId) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const key = await passwordKey(password, salt, ["encrypt"]);
  const aad = enc.encode(`NDRV Share key v1:${shareId}:${recipientId}`);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, contentKey));
  return { v: 1, kdf: "PBKDF2-SHA-256", iterations: PBKDF2_ITERATIONS,
    salt: toBase64Url(salt), iv: toBase64Url(iv), cipher: toBase64Url(cipher), recipientId };
}

export async function unwrapContentKey(envelope, password, shareId) {
  if (!envelope || envelope.v !== 1 || envelope.kdf !== "PBKDF2-SHA-256" || envelope.iterations !== PBKDF2_ITERATIONS ||
      !/^[A-Za-z0-9_-]{22}$/.test(envelope.salt || "") || !/^[A-Za-z0-9_-]{16}$/.test(envelope.iv || "") ||
      !/^[A-Za-z0-9_-]{64}$/.test(envelope.cipher || "") || !/^[a-f0-9-]{36}$/i.test(envelope.recipientId || ""))
    throw new Error("分享密鑰封裝格式無效");
  const key = await passwordKey(password, fromBase64Url(envelope.salt), ["decrypt"]);
  const aad = enc.encode(`NDRV Share key v1:${shareId}:${envelope.recipientId}`);
  try {
    const raw = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(envelope.iv), additionalData: aad },
      key, fromBase64Url(envelope.cipher)));
    if (raw.byteLength !== 32) throw new Error("invalid key size");
    return raw;
  } catch {
    throw new Error("密碼錯誤，或分享檔案已損壞");
  }
}

async function contentAesKey(raw, usages, shareId, purpose) {
  if (!(raw instanceof Uint8Array) || raw.byteLength !== 32) throw new Error("分享金鑰無效");
  const material = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode(shareId),
    info: enc.encode(`NDRV Share ${purpose} v1`) }, material, { name: "AES-GCM", length: 256 }, false, usages);
}

function metadataAad(shareId) { return enc.encode(`NDRV Share metadata v1:${shareId}`); }

export async function encryptMetadata(value, rawKey, shareId) {
  const iv = randomBytes(12), key = await contentAesKey(rawKey, ["encrypt"], shareId, "metadata");
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: metadataAad(shareId) },
    key, enc.encode(JSON.stringify(value))));
  return { iv: toBase64Url(iv), cipher: toBase64Url(cipher) };
}

export async function decryptMetadata(packet, rawKey, shareId) {
  if (!packet || !/^[A-Za-z0-9_-]{16}$/.test(packet.iv || "") || typeof packet.cipher !== "string" || packet.cipher.length > 4096)
    throw new Error("分享檔案資料不完整");
  const key = await contentAesKey(rawKey, ["decrypt"], shareId, "metadata");
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(packet.iv), additionalData: metadataAad(shareId) },
      key, fromBase64Url(packet.cipher));
    const value = JSON.parse(dec.decode(plain));
    if (typeof value.name !== "string" || value.name.length > 1024 || typeof value.mime !== "string" ||
        !Number.isSafeInteger(value.size) || value.size < 0)
      throw new Error("invalid metadata");
    return value;
  } catch {
    throw new Error("密碼錯誤，或分享檔案已損壞");
  }
}

function chunkIv(prefix, index) {
  if (!(prefix instanceof Uint8Array) || prefix.length !== 8 || !Number.isInteger(index) || index < 0 || index >= MAX_CHUNKS)
    throw new Error("分享區塊識別碼無效");
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  new DataView(iv.buffer).setUint32(8, index, false);
  return iv;
}

function chunkAad(shareId, index, size) {
  return enc.encode(`NDRV Share payload v1:${shareId}:${index}:${size}`);
}

export async function encryptChunk(plain, rawKey, shareId, noncePrefix, index) {
  const key = await contentAesKey(rawKey, ["encrypt"], shareId, "payload");
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: chunkIv(noncePrefix, index),
    additionalData: chunkAad(shareId, index, plain.byteLength) }, key, plain));
}

export async function decryptChunk(cipher, rawKey, shareId, noncePrefix, index, plainSize) {
  const key = await contentAesKey(rawKey, ["decrypt"], shareId, "payload");
  try {
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: chunkIv(noncePrefix, index),
      additionalData: chunkAad(shareId, index, plainSize) }, key, cipher));
    if (plain.byteLength !== plainSize) throw new Error("invalid chunk size");
    return plain;
  } catch {
    throw new Error("分享內容驗證失敗，資料可能已被修改");
  }
}
