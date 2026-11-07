const CHUNK_SIZE = 4 * 1024 * 1024;
const TAG_SIZE = 16;
const MAX_CHUNKS = 10000;
const MAX_FILE_BYTES = CHUNK_SIZE * MAX_CHUNKS;
const UUID_RE = /^[a-f0-9-]{36}$/i;
const TOKEN_HASH_RE = /^[a-f0-9]{64}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const NOTION_VERSION = "2026-03-11";
const NOTION_API = "https://api.notion.com/v1";

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = env.ALLOWED_ORIGIN || "";
  return {
    "Access-Control-Allow-Origin": origin === allowed ? allowed : "null",
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
    "Access-Control-Max-Age": "600",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
  };
}

function json(request, env, data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders(request, env), "Content-Type": "application/json; charset=utf-8" } });
}

function binary(request, env, body, status = 200) {
  return new Response(body, { status, headers: { ...corsHeaders(request, env), "Content-Type": "application/octet-stream", "Content-Disposition": "attachment" } });
}

function failure(request, env, message, status = 400) { return json(request, env, { error: message }, status); }

function allowedOrigin(request, env) {
  return Boolean(env.ALLOWED_ORIGIN) && request.headers.get("Origin") === env.ALLOWED_ORIGIN;
}

function bearer(request) {
  const value = request.headers.get("Authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7) : "";
}

function constantTimeEqual(left, right) {
  const a = new TextEncoder().encode(left || ""), b = new TextEncoder().encode(right || "");
  if (!a.length || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function requireAdmin(request, env) {
  return typeof env.ADMIN_TOKEN === "string" && env.ADMIN_TOKEN.length >= 32 && constantTimeEqual(bearer(request), env.ADMIN_TOKEN);
}

async function tokenHash(token) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  return [...digest].map((part) => part.toString(16).padStart(2, "0")).join("");
}

function validEnvelope(envelope, recipientId) {
  return envelope && envelope.v === 1 && envelope.kdf === "PBKDF2-SHA-256" && envelope.iterations === 600000 &&
    envelope.recipientId === recipientId && /^[A-Za-z0-9_-]{22}$/.test(envelope.salt || "") &&
    /^[A-Za-z0-9_-]{16}$/.test(envelope.iv || "") && /^[A-Za-z0-9_-]{64}$/.test(envelope.cipher || "");
}

async function readBytes(request, maxBytes) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > maxBytes) throw new Error("Request body is too large");
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader(), parts = [];
  let total = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) { await reader.cancel(); throw new Error("Request body is too large"); }
      parts.push(next.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
  return bytes;
}

async function readJson(request, maxBytes = 1024 * 1024) {
  return JSON.parse(new TextDecoder().decode(await readBytes(request, maxBytes)));
}

function storageConfigured(env) {
  return typeof env.NOTION_TOKEN === "string" && env.NOTION_TOKEN.length > 20 &&
    typeof env.NOTION_ROOT_PAGE_ID === "string" && env.NOTION_ROOT_PAGE_ID.length >= 20;
}

async function notionRequest(env, path, init = {}) {
  if (!storageConfigured(env)) throw new Error("Notion Drive storage is not configured");
  const headers = new Headers(init.headers || {});
  headers.set("Authorization", `Bearer ${env.NOTION_TOKEN}`);
  headers.set("Notion-Version", NOTION_VERSION);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const fetcher = env.NOTION_FETCH || fetch;
  const response = await fetcher(`${NOTION_API}${path}`, { ...init, headers });
  if (!response.ok) throw new Error(`Notion API request failed (${response.status})`);
  return response;
}

async function notionJson(env, path, init = {}) {
  return notionRequest(env, path, init).then((response) => response.json());
}

async function createStoragePage(env, shareId) {
  const title = `NDSHARE1.${shareId}`;
  return notionJson(env, "/pages", {
    method: "POST",
    body: JSON.stringify({
      parent: { type: "page_id", page_id: env.NOTION_ROOT_PAGE_ID },
      properties: { title: { type: "title", title: [{ type: "text", text: { content: title } }] } },
    }),
  });
}

async function trashStoragePage(env, pageId) {
  if (!pageId) return;
  await notionRequest(env, `/pages/${encodeURIComponent(pageId)}`, {
    method: "PATCH",
    body: JSON.stringify({ in_trash: true }),
  });
}

function notionFileName(shareId, chunkIndex) {
  return `NDS-${shareId}-${String(chunkIndex).padStart(5, "0")}.bin`;
}

async function uploadNotionChunk(env, pageId, shareId, chunkIndex, bytes) {
  const filename = notionFileName(shareId, chunkIndex);
  const upload = await notionJson(env, "/file_uploads", {
    method: "POST",
    body: JSON.stringify({ filename, content_type: "application/octet-stream" }),
  });
  if (!upload?.id) throw new Error("Notion did not return a file upload ID");
  const form = new FormData();
  form.append("file", new Blob([bytes], { type: "application/octet-stream" }), filename);
  await notionRequest(env, `/file_uploads/${encodeURIComponent(upload.id)}/send`, { method: "POST", body: form });
  const attached = await notionJson(env, `/blocks/${encodeURIComponent(pageId)}/children`, {
    method: "PATCH",
    body: JSON.stringify({ children: [{ object: "block", type: "file", file: { type: "file_upload", file_upload: { id: upload.id } } }] }),
  });
  const blockId = attached?.results?.[0]?.id;
  if (!blockId) throw new Error("Notion did not return the stored file block ID");
  return blockId;
}

function allowedNotionFileUrl(input) {
  let url;
  try { url = new URL(input); } catch { return false; }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443")) return false;
  const host = url.hostname.toLowerCase();
  return host === "file.notion.so" || host === "files.notion.so" || host === "notion-static.com" ||
    host.endsWith(".notion-static.com") || host.endsWith(".notionusercontent.com") ||
    host === "amazonaws.com" || host.endsWith(".amazonaws.com");
}

async function fetchNotionFile(env, initialUrl) {
  let url = initialUrl;
  const fetcher = env.NOTION_FETCH || fetch;
  for (let redirect = 0; redirect <= 4; redirect++) {
    if (!allowedNotionFileUrl(url)) throw new Error("Notion returned a disallowed file URL");
    const response = await fetcher(url, { redirect: "manual" });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get("Location");
    if (!location) throw new Error("Notion file redirect did not include a location");
    url = new URL(location, url).href;
  }
  throw new Error("Too many Notion file redirects");
}

async function createShare(request, env) {
  if (!(await requireAdmin(request, env))) return failure(request, env, "管理者驗證失敗。", 401);
  let body;
  try { body = await readJson(request); } catch { return failure(request, env, "分享資料格式無效。", 400); }
  const id = String(body.id || ""), recipients = body.recipients;
  const chunkCount = Number(body.chunkCount), plaintextSize = Number(body.plaintextSize), chunkSize = Number(body.chunkSize);
  const maxRecipients = Math.min(30, Math.max(1, Number(env.MAX_RECIPIENTS || 30)));
  if (!UUID_RE.test(id) || !body.metadata || !/^[A-Za-z0-9_-]{16}$/.test(body.metadata.iv || "") ||
      !B64URL_RE.test(body.metadata.cipher || "") || body.metadata.cipher.length > 4096 ||
      !/^[A-Za-z0-9_-]{11}$/.test(body.noncePrefix || "") || chunkSize !== CHUNK_SIZE ||
      !Number.isSafeInteger(chunkCount) || chunkCount < 1 || chunkCount > MAX_CHUNKS ||
      !Number.isSafeInteger(plaintextSize) || plaintextSize < 1 || plaintextSize > MAX_FILE_BYTES ||
      chunkCount !== Math.ceil(plaintextSize / CHUNK_SIZE) || !Array.isArray(recipients) ||
      recipients.length < 1 || recipients.length > maxRecipients)
    return failure(request, env, "分享設定無效，請重新建立。", 400);

  const ids = new Set(), hashes = new Set();
  for (const recipient of recipients) {
    if (!UUID_RE.test(recipient.id || "") || typeof recipient.label !== "string" || !recipient.label.trim() || recipient.label.length > 80 ||
        !TOKEN_HASH_RE.test(recipient.tokenHash || "") || hashes.has(recipient.tokenHash) || ids.has(recipient.id) ||
        !validEnvelope(recipient.envelope, recipient.id)) return failure(request, env, "收件人權限資料無效。", 400);
    ids.add(recipient.id); hashes.add(recipient.tokenHash);
  }

  const existing = await env.DB.prepare("SELECT id FROM shares WHERE id = ?").bind(id).first();
  if (existing) return failure(request, env, "分享識別碼已存在，請重試。", 409);
  if (!storageConfigured(env)) return failure(request, env, "Notion Drive 儲存尚未設定。", 503);
  let storagePage;
  try { storagePage = await createStoragePage(env, id); }
  catch { return failure(request, env, "無法在 Notion Drive 建立分享儲存頁；請檢查 integration 權限與根頁面設定。", 502); }
  if (!storagePage?.id) return failure(request, env, "Notion Drive 沒有建立分享儲存頁。", 502);
  const createdAt = new Date().toISOString();
  const statements = [env.DB.prepare("INSERT INTO shares (id, storage_page_id, metadata, nonce_prefix, chunk_size, chunk_count, plaintext_size, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)")
    .bind(id, storagePage.id, JSON.stringify(body.metadata), body.noncePrefix, chunkSize, chunkCount, plaintextSize, createdAt),
    ...recipients.map((recipient) => env.DB.prepare("INSERT INTO recipients (id, share_id, label, token_hash, envelope, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(recipient.id, id, recipient.label.trim(), recipient.tokenHash, JSON.stringify(recipient.envelope), createdAt))];
  try { await env.DB.batch(statements); }
  catch (error) { await trashStoragePage(env, storagePage.id).catch(() => {}); throw error; }
  return json(request, env, { id, state: "pending" }, 201);
}

async function uploadChunk(request, env, id, index) {
  if (!(await requireAdmin(request, env))) return failure(request, env, "管理者驗證失敗。", 401);
  if (!UUID_RE.test(id) || !/^\d{1,5}$/.test(index)) return failure(request, env, "區塊位置無效。", 400);
  const chunkIndex = Number(index);
  const share = await env.DB.prepare("SELECT * FROM shares WHERE id = ? AND state = 'pending'").bind(id).first();
  if (!share) return failure(request, env, "找不到待完成的分享。", 404);
  if (chunkIndex < 0 || chunkIndex >= share.chunk_count) return failure(request, env, "區塊位置超出範圍。", 400);
  const plainLength = Math.min(CHUNK_SIZE, share.plaintext_size - chunkIndex * CHUNK_SIZE);
  const expectedLength = plainLength + TAG_SIZE;
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength && declaredLength !== expectedLength) return failure(request, env, "加密區塊長度不符。", 400);
  let bytes;
  try { bytes = await readBytes(request, expectedLength); } catch { return failure(request, env, "加密區塊長度不符。", 400); }
  if (bytes.byteLength !== expectedLength) return failure(request, env, "加密區塊長度不符。", 400);
  const existing = await env.DB.prepare("SELECT byte_length FROM uploaded_chunks WHERE share_id = ? AND chunk_index = ?").bind(id, chunkIndex).first();
  if (existing) return Number(existing.byte_length) === bytes.byteLength
    ? json(request, env, { index: chunkIndex, stored: true })
    : failure(request, env, "已儲存的區塊長度不符。", 409);
  const blockId = await uploadNotionChunk(env, share.storage_page_id, id, chunkIndex, bytes);
  await env.DB.prepare("INSERT INTO uploaded_chunks (share_id, chunk_index, byte_length, notion_block_id) VALUES (?, ?, ?, ?)")
    .bind(id, chunkIndex, bytes.byteLength, blockId).run();
  return json(request, env, { index: chunkIndex, stored: true });
}

async function commitShare(request, env, id) {
  if (!(await requireAdmin(request, env))) return failure(request, env, "管理者驗證失敗。", 401);
  const share = await env.DB.prepare("SELECT id, chunk_count, state FROM shares WHERE id = ?").bind(id).first();
  if (share?.state === "active") return json(request, env, { id, state: "active" });
  if (!share || share.state !== "pending") return failure(request, env, "找不到待完成的分享。", 404);
  const total = await env.DB.prepare("SELECT COUNT(*) AS count FROM uploaded_chunks WHERE share_id = ?").bind(id).first();
  if (Number(total?.count) !== Number(share.chunk_count)) return failure(request, env, "尚未收到所有加密區塊。", 409);
  await env.DB.prepare("UPDATE shares SET state = 'active' WHERE id = ?").bind(id).run();
  return json(request, env, { id, state: "active" });
}

async function adminShares(request, env) {
  if (!(await requireAdmin(request, env))) return failure(request, env, "管理者驗證失敗。", 401);
  const rows = await env.DB.prepare("SELECT s.id, s.metadata, s.plaintext_size, s.state, s.created_at, r.id AS recipient_id, r.label, r.revoked FROM shares s LEFT JOIN recipients r ON r.share_id = s.id ORDER BY s.created_at DESC")
    .all();
  const map = new Map();
  for (const row of rows.results || []) {
    let share = map.get(row.id);
    if (!share) {
      share = { id: row.id, plaintextSize: row.plaintext_size, state: row.state, createdAt: row.created_at, recipients: [] };
      map.set(row.id, share);
    }
    if (row.recipient_id) share.recipients.push({ id: row.recipient_id, label: row.label, revoked: Boolean(row.revoked) });
  }
  return json(request, env, { shares: [...map.values()] });
}

async function authorizeRecipient(request, env, id) {
  if (!UUID_RE.test(id)) return null;
  const token = bearer(request);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const hash = await tokenHash(token);
  return env.DB.prepare("SELECT r.id AS recipient_id, r.label, r.envelope, s.id, s.metadata, s.nonce_prefix, s.chunk_size, s.chunk_count, s.plaintext_size FROM recipients r JOIN shares s ON s.id = r.share_id WHERE r.share_id = ? AND r.token_hash = ? AND r.revoked = 0 AND s.state = 'active'")
    .bind(id, hash).first();
}

async function getPublicShare(request, env, id) {
  const access = await authorizeRecipient(request, env, id);
  if (!access) return failure(request, env, "分享連結無效、已撤銷或已到期。", 404);
  return json(request, env, { id: access.id, metadata: JSON.parse(access.metadata), noncePrefix: access.nonce_prefix,
    chunkSize: access.chunk_size, chunkCount: access.chunk_count, plaintextSize: access.plaintext_size,
    envelope: JSON.parse(access.envelope), recipientLabel: access.label });
}

async function getPublicChunk(request, env, id, index) {
  const access = await authorizeRecipient(request, env, id);
  if (!access) return failure(request, env, "分享連結無效、已撤銷或已到期。", 404);
  if (!/^\d{1,5}$/.test(index)) return failure(request, env, "區塊位置無效。", 400);
  const chunkIndex = Number(index);
  if (chunkIndex < 0 || chunkIndex >= access.chunk_count) return failure(request, env, "區塊位置超出範圍。", 404);
  const stored = await env.DB.prepare("SELECT notion_block_id FROM uploaded_chunks WHERE share_id = ? AND chunk_index = ?").bind(id, chunkIndex).first();
  if (!stored?.notion_block_id) return failure(request, env, "分享區塊不存在。", 404);
  const block = await notionJson(env, `/blocks/${encodeURIComponent(stored.notion_block_id)}`);
  const fileUrl = block?.file?.file?.url || block?.file?.url;
  if (!fileUrl) return failure(request, env, "Notion Drive 找不到這個加密區塊。", 404);
  const file = await fetchNotionFile(env, fileUrl);
  if (!file.ok || !file.body) return failure(request, env, "無法從 Notion Drive 讀取加密區塊。", 502);
  return binary(request, env, file.body);
}

async function revokeRecipient(request, env, id, recipientId) {
  if (!(await requireAdmin(request, env))) return failure(request, env, "管理者驗證失敗。", 401);
  if (!UUID_RE.test(id) || !UUID_RE.test(recipientId)) return failure(request, env, "分享識別碼無效。", 400);
  const result = await env.DB.prepare("UPDATE recipients SET revoked = 1, token_hash = ? WHERE id = ? AND share_id = ? AND revoked = 0")
    .bind(`revoked:${crypto.randomUUID()}`, recipientId, id).run();
  if (!result.meta?.changes) return failure(request, env, "找不到有效的收件人權限。", 404);
  return json(request, env, { revoked: true });
}

async function deleteShare(request, env, id) {
  if (!(await requireAdmin(request, env))) return failure(request, env, "管理者驗證失敗。", 401);
  if (!UUID_RE.test(id)) return failure(request, env, "分享識別碼無效。", 400);
  const share = await env.DB.prepare("SELECT id, storage_page_id FROM shares WHERE id = ?").bind(id).first();
  if (!share) return failure(request, env, "找不到這份分享。", 404);
  await env.DB.prepare("UPDATE shares SET state = 'deleting' WHERE id = ?").bind(id).run();
  await trashStoragePage(env, share.storage_page_id);
  await env.DB.prepare("DELETE FROM shares WHERE id = ?").bind(id).run();
  return json(request, env, { deleted: true });
}

async function route(request, env) {
    if (!allowedOrigin(request, env)) return failure(request, env, "不允許的網站來源。", 403);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    const url = new URL(request.url), path = url.pathname.replace(/\/+$/, "") || "/";
    if (path === "/api/admin/shares" && request.method === "POST") return createShare(request, env);
    if (path === "/api/admin/shares" && request.method === "GET") return adminShares(request, env);
    let match = path.match(/^\/api\/admin\/shares\/([a-f0-9-]{36})\/chunks\/(\d{1,5})$/i);
    if (match && request.method === "PUT") return uploadChunk(request, env, match[1], match[2]);
    match = path.match(/^\/api\/admin\/shares\/([a-f0-9-]{36})\/commit$/i);
    if (match && request.method === "POST") return commitShare(request, env, match[1]);
    match = path.match(/^\/api\/admin\/shares\/([a-f0-9-]{36})\/recipients\/([a-f0-9-]{36})$/i);
    if (match && request.method === "DELETE") return revokeRecipient(request, env, match[1], match[2]);
    match = path.match(/^\/api\/admin\/shares\/([a-f0-9-]{36})$/i);
    if (match && request.method === "DELETE") return deleteShare(request, env, match[1]);
    match = path.match(/^\/api\/share\/([a-f0-9-]{36})\/chunks\/(\d{1,5})$/i);
    if (match && request.method === "GET") return getPublicChunk(request, env, match[1], match[2]);
    match = path.match(/^\/api\/share\/([a-f0-9-]{36})$/i);
    if (match && request.method === "GET") return getPublicShare(request, env, match[1]);
    return failure(request, env, "找不到 API 路徑。", 404);
}

export default {
  async fetch(request, env) {
    try { return await route(request, env); }
    catch { return failure(request, env, "分享服務暫時無法完成此操作，請稍後重試。", 500); }
  }
};
