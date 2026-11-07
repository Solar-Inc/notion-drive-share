import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, toBase64Url, fromBase64Url, wrapContentKey, unwrapContentKey,
  encryptMetadata, decryptMetadata, encryptChunk, decryptChunk } from "../crypto.js";

test("每位收件人可使用自己的密碼解開同一份檔案金鑰", async () => {
  const key = randomBytes(32), shareId = crypto.randomUUID();
  const alice = await wrapContentKey(key, "Alice-Password-72913", shareId, crypto.randomUUID());
  const bob = await wrapContentKey(key, "Bob-Password-31509", shareId, crypto.randomUUID());
  assert.deepEqual(await unwrapContentKey(alice, "Alice-Password-72913", shareId), key);
  assert.deepEqual(await unwrapContentKey(bob, "Bob-Password-31509", shareId), key);
  await assert.rejects(unwrapContentKey(bob, "Alice-Password-72913", shareId));
  await assert.rejects(unwrapContentKey(alice, "Wrong-Password-72913", shareId));
  await assert.rejects(unwrapContentKey(alice, "Alice-Password-72913", crypto.randomUUID()));
  assert.notEqual(alice.salt, bob.salt);
  assert.notEqual(alice.cipher, bob.cipher);
});

test("封裝綁定收件人，禁止更改 KDF 參數", async () => {
  const key = randomBytes(32), shareId = crypto.randomUUID();
  const envelope = await wrapContentKey(key, "Per-Recipient-12879", shareId, crypto.randomUUID());
  await assert.rejects(unwrapContentKey({ ...envelope, recipientId: crypto.randomUUID() }, "Per-Recipient-12879", shareId));
  await assert.rejects(unwrapContentKey({ ...envelope, iterations: 1 }, "Per-Recipient-12879", shareId));
});

test("檔案 metadata 加密，其他分享的金鑰或 ID 不能解密", async () => {
  const key = randomBytes(32), shareId = crypto.randomUUID();
  const metadata = { name: "私人檔案.txt", mime: "text/plain", size: 8 };
  const packet = await encryptMetadata(metadata, key, shareId);
  assert.deepEqual(await decryptMetadata(packet, key, shareId), metadata);
  assert.ok(!JSON.stringify(packet).includes(metadata.name));
  await assert.rejects(decryptMetadata(packet, randomBytes(32), shareId));
  await assert.rejects(decryptMetadata(packet, key, crypto.randomUUID()));
});

test("區塊內容、順序、分享 ID 和長度都會驗證", async () => {
  const key = randomBytes(32), nonce = randomBytes(8), shareId = crypto.randomUUID();
  const plain = new TextEncoder().encode("驗證分享內容");
  const cipher = await encryptChunk(plain, key, shareId, nonce, 0);
  assert.deepEqual(await decryptChunk(cipher, key, shareId, nonce, 0, plain.length), plain);
  const changed = cipher.slice(); changed[0] ^= 1;
  await assert.rejects(decryptChunk(changed, key, shareId, nonce, 0, plain.length));
  await assert.rejects(decryptChunk(cipher, key, shareId, nonce, 1, plain.length));
  await assert.rejects(decryptChunk(cipher, key, crypto.randomUUID(), nonce, 0, plain.length));
  await assert.rejects(decryptChunk(cipher, key, shareId, nonce, 0, plain.length + 1));
});

test("隨機連結 token 的 base64url 可往返且不含 URL 保留符號", () => {
  const token = randomBytes(32), text = toBase64Url(token);
  assert.match(text, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(fromBase64Url(text), token);
});
