import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import worker from "../src/index.js";
import { CHUNK_SIZE, randomBytes, toBase64Url, sha256Hex, wrapContentKey, unwrapContentKey,
  encryptMetadata, decryptMetadata, encryptChunk, decryptChunk } from "../../share/crypto.js";

const ORIGIN = "https://solar-inc.github.io";
const ADMIN = "Admin-Only-Super-Long-Random-Test-Key-572916";

class D1Statement {
  constructor(db, sql) { this.db = db; this.sql = sql; this.args = []; }
  bind(...args) { this.args = args; return this; }
  async first() { return this.db.prepare(this.sql).get(...this.args) || null; }
  async all() { return { results: this.db.prepare(this.sql).all(...this.args) }; }
  async run() { const result = this.db.prepare(this.sql).run(...this.args); return { success: true, meta: { changes: Number(result.changes) } }; }
}

class D1Mock {
  constructor() { this.db = new DatabaseSync(":memory:"); this.db.exec(readFileSync(new URL("../schema.sql", import.meta.url), "utf8")); }
  prepare(sql) { return new D1Statement(this.db, sql); }
  async batch(statements) {
    this.db.exec("BEGIN");
    try { const results = []; for (const statement of statements) results.push(await statement.run()); this.db.exec("COMMIT"); return results; }
    catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
}

class R2Mock {
  constructor() { this.objects = new Map(); this.failDelete = false; }
  async put(key, value) { this.objects.set(key, new Uint8Array(value).slice()); }
  async get(key) { const value = this.objects.get(key); return value ? { body: value.slice() } : null; }
  async delete(keys) { if (this.failDelete) throw new Error("storage failure"); for (const key of Array.isArray(keys) ? keys : [keys]) this.objects.delete(key); }
}

function makeEnv() { return { ALLOWED_ORIGIN: ORIGIN, ADMIN_TOKEN: ADMIN, MAX_RECIPIENTS: "30", DB: new D1Mock(), SHARES: new R2Mock() }; }

async function call(env, method, path, body, token = ADMIN, origin = ORIGIN) {
  const headers = { Origin: origin, Authorization: `Bearer ${token}` };
  const payload = body === undefined ? undefined : body instanceof Uint8Array ? body : JSON.stringify(body);
  return worker.fetch(new Request(`https://share-api.example${path}`, { method, headers, body: payload }), env);
}

async function fixture() {
  const env = makeEnv(), id = crypto.randomUUID(), key = randomBytes(32), nonce = randomBytes(8);
  const plain = new TextEncoder().encode("這是一份只分享給指定收件人的檔案。");
  const recipients = [];
  for (const [label, password] of [["Alice", "Alice-Unique-Password-74829"], ["Bob", "Bob-Unique-Password-91832"]]) {
    const recipientId = crypto.randomUUID(), token = toBase64Url(randomBytes(32));
    recipients.push({ id: recipientId, label, password, token, tokenHash: await sha256Hex(token),
      envelope: await wrapContentKey(key, password, id, recipientId) });
  }
  const metadata = await encryptMetadata({ name: "私人文字.txt", mime: "text/plain", size: plain.length }, key, id);
  const body = { id, metadata, noncePrefix: toBase64Url(nonce), chunkSize: CHUNK_SIZE, chunkCount: 1, plaintextSize: plain.length,
    recipients: recipients.map(({ password, token, ...recipient }) => recipient) };
  const cipher = await encryptChunk(plain, key, id, nonce, 0);
  return { env, id, key, nonce, plain, recipients, body, cipher };
}

test("權限、建立、區塊驗證、提交、個別密碼和個別撤銷完整流程", async () => {
  const f = await fixture(), { env, id, recipients } = f;
  assert.equal((await call(env, "POST", "/api/admin/shares", f.body, "wrong")).status, 401);
  assert.equal((await call(env, "POST", "/api/admin/shares", f.body, ADMIN, "https://attacker.example")).status, 403);
  assert.equal((await call(env, "POST", "/api/admin/shares", f.body)).status, 201);
  assert.equal((await call(env, "GET", `/api/share/${id}`, undefined, recipients[0].token)).status, 404);
  assert.equal((await call(env, "POST", `/api/admin/shares/${id}/commit`, {})).status, 409);
  assert.equal((await call(env, "PUT", `/api/admin/shares/${id}/chunks/0`, f.cipher.slice(1))).status, 400);
  assert.equal((await call(env, "PUT", `/api/admin/shares/${id}/chunks/0`, f.cipher)).status, 200);
  assert.equal((await call(env, "POST", `/api/admin/shares/${id}/commit`, {})).status, 200);
  assert.equal((await call(env, "POST", `/api/admin/shares/${id}/commit`, {})).status, 200);

  const alice = await (await call(env, "GET", `/api/share/${id}`, undefined, recipients[0].token)).json();
  const bob = await (await call(env, "GET", `/api/share/${id}`, undefined, recipients[1].token)).json();
  assert.notEqual(alice.envelope.recipientId, bob.envelope.recipientId);
  const aliceKey = await unwrapContentKey(alice.envelope, recipients[0].password, id);
  assert.deepEqual(await decryptMetadata(alice.metadata, aliceKey, id), { name: "私人文字.txt", mime: "text/plain", size: f.plain.length });
  await assert.rejects(unwrapContentKey(bob.envelope, recipients[0].password, id));
  const response = await call(env, "GET", `/api/share/${id}/chunks/0`, undefined, recipients[0].token);
  assert.deepEqual(await decryptChunk(new Uint8Array(await response.arrayBuffer()), aliceKey, id, f.nonce, 0, f.plain.length), f.plain);
  assert.equal((await call(env, "GET", "/api/admin/shares", undefined, recipients[0].token)).status, 401);

  const saved = env.DB.db.prepare("SELECT * FROM recipients WHERE id = ?").get(recipients[0].id);
  assert.equal(saved.token_hash, recipients[0].tokenHash);
  assert.ok(!JSON.stringify(saved).includes(recipients[0].token));
  assert.ok(!JSON.stringify(saved).includes(recipients[0].password));
  assert.notDeepEqual(env.SHARES.objects.values().next().value, f.plain);

  assert.equal((await call(env, "DELETE", `/api/admin/shares/${id}/recipients/${recipients[1].id}`)).status, 200);
  assert.equal((await call(env, "GET", `/api/share/${id}`, undefined, recipients[1].token)).status, 404);
  assert.equal((await call(env, "GET", `/api/share/${id}/chunks/0`, undefined, recipients[1].token)).status, 404);
  assert.equal((await call(env, "GET", `/api/share/${id}`, undefined, recipients[0].token)).status, 200);
  assert.equal((await call(env, "DELETE", `/api/admin/shares/${id}`)).status, 200);
  assert.equal(env.SHARES.objects.size, 0);
  assert.equal(env.DB.db.prepare("SELECT COUNT(*) AS count FROM recipients").get().count, 0);
  assert.equal((await call(env, "GET", `/api/share/${id}`, undefined, recipients[0].token)).status, 404);
});

test("刪除儲存區失敗時先停止存取，並保留可重試狀態", async () => {
  const f = await fixture(), { env, id } = f;
  await call(env, "POST", "/api/admin/shares", f.body);
  await call(env, "PUT", `/api/admin/shares/${id}/chunks/0`, f.cipher);
  await call(env, "POST", `/api/admin/shares/${id}/commit`, {});
  env.SHARES.failDelete = true;
  assert.equal((await call(env, "DELETE", `/api/admin/shares/${id}`)).status, 500);
  assert.equal((await call(env, "GET", `/api/share/${id}`, undefined, f.recipients[0].token)).status, 404);
  const list = await (await call(env, "GET", "/api/admin/shares")).json();
  assert.equal(list.shares[0].state, "deleting");
  env.SHARES.failDelete = false;
  assert.equal((await call(env, "DELETE", `/api/admin/shares/${id}`)).status, 200);
});

test("重複連結 token、異常大小與超量區塊會被拒絕", async () => {
  const f = await fixture();
  const duplicate = structuredClone(f.body);
  duplicate.recipients[1].tokenHash = duplicate.recipients[0].tokenHash;
  assert.equal((await call(f.env, "POST", "/api/admin/shares", duplicate)).status, 400);
  assert.equal((await call(f.env, "POST", "/api/admin/shares", { ...f.body, chunkCount: 10001 })).status, 400);
  await call(f.env, "POST", "/api/admin/shares", f.body);
  assert.equal((await call(f.env, "PUT", `/api/admin/shares/${f.id}/chunks/0`, new Uint8Array(f.cipher.length + 1))).status, 400);
  assert.equal(f.env.SHARES.objects.size, 0);
});
