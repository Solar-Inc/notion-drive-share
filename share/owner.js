import { CHUNK_SIZE, MAX_CHUNKS, randomBytes, toBase64Url, sha256Hex, wrapContentKey, encryptMetadata, encryptChunk } from "./crypto.js";

const $ = (selector) => document.querySelector(selector);
const apiInput = $("#apiBase"), tokenInput = $("#adminToken");
const recipientsRoot = $("#recipients"), template = $("#recipientTemplate");
const apiKey = "ndriveShareApiBase", tokenKey = "ndriveShareAdminToken", labelsKey = "ndriveShareLocalLabels";
apiInput.value = localStorage.getItem(apiKey) || "";
tokenInput.value = sessionStorage.getItem(tokenKey) || "";

function apiBase() {
  const value = apiInput.value.trim().replace(/\/+$/, "");
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error("請輸入有效的 Worker API 網址"); }
  if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") throw new Error("分享 API 必須使用 HTTPS");
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/")
    throw new Error("API 網址只需填入網站來源，不要包含路徑或查詢參數");
  return parsed.origin;
}

function adminToken() {
  const value = tokenInput.value.trim();
  if (value.length < 32) throw new Error("請輸入 Worker 管理密鑰");
  return value;
}

async function request(path, { method = "GET", body, token = adminToken(), headers = {} } = {}) {
  const response = await fetch(`${apiBase()}${path}`, { method, cache: "no-store", headers: { Authorization: `Bearer ${token}`,
    ...(body instanceof ArrayBuffer || body instanceof Uint8Array ? { "Content-Type": "application/octet-stream" } : body ? { "Content-Type": "application/json" } : {}), ...headers }, body });
  const data = response.headers.get("content-type")?.includes("application/json") ? await response.json() : null;
  if (!response.ok) throw new Error(data?.error || `分享服務回應錯誤（${response.status}）`);
  return data;
}

function setStatus(element, message, state = "") {
  element.textContent = message;
  element.className = `hint ${state}`.trim();
}

function addRecipient(label = "", password = "") {
  const fragment = template.content.cloneNode(true), row = fragment.querySelector(".recipient-row");
  row.querySelector(".recipient-label").value = label;
  row.querySelector(".recipient-password").value = password;
  row.querySelector(".remove-recipient").addEventListener("click", () => {
    if (recipientsRoot.children.length <= 1) return;
    row.remove();
  });
  recipientsRoot.append(fragment);
}

function readRecipients() {
  const entries = [...recipientsRoot.querySelectorAll(".recipient-row")].map((row) => ({
    label: row.querySelector(".recipient-label").value.trim(),
    password: row.querySelector(".recipient-password").value,
  }));
  if (!entries.length) throw new Error("至少需要一位收件人");
  if (entries.some((entry) => !entry.label || entry.label.length > 80 || entry.password.length < 12))
    throw new Error("請填寫收件人名稱，並設定至少 12 個字元的密碼");
  if (new Set(entries.map((entry) => entry.password)).size !== entries.length)
    throw new Error("每位收件人必須使用不同密碼");
  if (entries.length > 30) throw new Error("單次最多可新增 30 位收件人");
  return entries;
}

async function createShare(file, entries, token, status) {
  const shareId = crypto.randomUUID(), contentKey = randomBytes(32), noncePrefix = randomBytes(8);
  const chunkCount = Math.ceil(file.size / CHUNK_SIZE);
  if (!chunkCount) throw new Error("空檔案目前不能建立分享");
  if (chunkCount > MAX_CHUNKS) throw new Error("檔案超過分享上限（40 GiB）");
  const metadata = await encryptMetadata({ name: file.name, mime: file.type || "application/octet-stream", size: file.size }, contentKey, shareId);
  const recipients = [];
  for (const entry of entries) {
    const recipientId = crypto.randomUUID(), viewToken = toBase64Url(randomBytes(32));
    const envelope = await wrapContentKey(contentKey, entry.password, shareId, recipientId);
    recipients.push({ id: recipientId, label: entry.label, tokenHash: await sha256Hex(viewToken), envelope, viewToken, password: entry.password });
  }
  let created = false, committed = false;
  try {
    await request("/api/admin/shares", { method: "POST", token, body: JSON.stringify({ id: shareId, metadata, noncePrefix: toBase64Url(noncePrefix),
      chunkSize: CHUNK_SIZE, chunkCount, plaintextSize: file.size, recipients: recipients.map(({ viewToken, password, ...recipient }) => recipient) }) });
    created = true;
    const button = $("#createShareButton");
    for (let index = 0; index < chunkCount; index++) {
      const start = index * CHUNK_SIZE, end = Math.min(start + CHUNK_SIZE, file.size);
      const plain = new Uint8Array(await file.slice(start, end).arrayBuffer());
      const cipher = await encryptChunk(plain, contentKey, shareId, noncePrefix, index);
      plain.fill(0);
      await request(`/api/admin/shares/${encodeURIComponent(shareId)}/chunks/${index}`, { method: "PUT", token, body: cipher });
      setStatus(status, `加密並上傳中：${index + 1} / ${chunkCount} 個區塊`);
      button.textContent = `上傳中 ${Math.round((index + 1) / chunkCount * 100)}%`;
    }
    await request(`/api/admin/shares/${encodeURIComponent(shareId)}/commit`, { method: "POST", token, body: "{}" });
    committed = true;
    return { shareId, items: recipients.map((recipient) => ({
      id: recipient.id, label: recipient.label, password: recipient.password,
      url: makeShareUrl(shareId, recipient.viewToken),
    })) };
  } catch (error) {
    if (created && !committed) {
      await request(`/api/admin/shares/${encodeURIComponent(shareId)}`, { method: "DELETE", token }).catch(() => {});
    }
    throw error;
  } finally { contentKey.fill(0); }
}

function makeShareUrl(shareId, viewToken) {
  const url = new URL("view.html", location.href);
  url.searchParams.set("id", shareId);
  url.searchParams.set("api", apiBase());
  url.hash = `t=${encodeURIComponent(viewToken)}`;
  return url.href;
}

function addResult(result) {
  const row = document.createElement("article");
  row.className = "result-item";
  const top = document.createElement("div"); top.className = "result-top";
  const name = document.createElement("span"); name.className = "result-name"; name.textContent = result.label;
  const controls = document.createElement("div"); controls.className = "result-controls";
  const linkButton = document.createElement("button"); linkButton.className = "copy-button"; linkButton.textContent = "複製專屬網址";
  linkButton.onclick = async () => { await navigator.clipboard.writeText(result.url); linkButton.textContent = "已複製網址"; };
  const passButton = document.createElement("button"); passButton.className = "copy-button"; passButton.textContent = "複製密碼";
  passButton.onclick = async () => { await navigator.clipboard.writeText(result.password); passButton.textContent = "已複製密碼"; };
  controls.append(linkButton, passButton); top.append(name, controls);
  const link = document.createElement("code"); link.className = "result-link"; link.textContent = result.url;
  const password = document.createElement("div"); password.className = "result-password"; password.textContent = `專屬密碼：${result.password}`;
  row.append(top, link, password); $("#resultList").append(row);
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"]; let size = value, index = -1;
  do { size /= 1024; index++; } while (size >= 1024 && index < units.length - 1);
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[index]}`;
}

async function loadShares() {
  const root = $("#shareList"); root.replaceChildren();
  const data = await request("/api/admin/shares");
  if (!data.shares?.length) { const empty = document.createElement("p"); empty.className = "empty"; empty.textContent = "目前沒有分享。"; root.append(empty); return; }
  for (const share of data.shares) {
    const card = document.createElement("article"); card.className = "share-card";
    const head = document.createElement("div"); head.className = "share-card-head";
    const title = document.createElement("div");
    let localLabels = {};
    try { localLabels = JSON.parse(localStorage.getItem(labelsKey) || "{}"); } catch {}
    const h = document.createElement("h3"); h.textContent = localLabels[share.id] || `分享 ${share.id.slice(0, 8)}`;
    const stateLabel = { active: "已發佈", pending: "上傳未完成", deleting: "待清理" }[share.state] || share.state;
    const small = document.createElement("small"); small.textContent = `${formatBytes(share.plaintextSize)} · ${stateLabel} · ${new Date(share.createdAt).toLocaleString("zh-TW")}`;
    title.append(h, small);
    const revokeAll = document.createElement("button"); revokeAll.className = "revoke"; revokeAll.textContent = "撤銷整份分享";
    revokeAll.onclick = async () => { if (!confirm("撤銷整份分享後，所有連結都會失效。確定繼續？")) return; await request(`/api/admin/shares/${encodeURIComponent(share.id)}`, { method: "DELETE" }); await loadShares(); };
    head.append(title, revokeAll); card.append(head);
    for (const recipient of share.recipients || []) {
      const line = document.createElement("div"); line.className = "recipient-access";
      const label = document.createElement("span"); label.textContent = `${recipient.label}${recipient.revoked ? " · 已撤銷" : " · 可存取"}`;
      if (!recipient.revoked) {
        const revoke = document.createElement("button"); revoke.className = "revoke"; revoke.textContent = "撤銷此人";
        revoke.onclick = async () => { if (!confirm(`撤銷「${recipient.label}」的存取權？`)) return; await request(`/api/admin/shares/${encodeURIComponent(share.id)}/recipients/${encodeURIComponent(recipient.id)}`, { method: "DELETE" }); await loadShares(); };
        line.append(label, revoke);
      } else line.append(label);
      card.append(line);
    }
    root.append(card);
  }
}

$("#addRecipientButton").addEventListener("click", () => addRecipient());
$("#connectButton").addEventListener("click", async () => {
  const status = $("#connectionStatus"), button = $("#connectButton");
  try {
    button.disabled = true; status.textContent = "連線中…";
    const base = apiBase(), token = adminToken();
    localStorage.setItem(apiKey, base); sessionStorage.setItem(tokenKey, token);
    await loadShares(); $("#connectionDot").classList.add("connected");
    setStatus(status, "已連線；管理密鑰只保留在目前分頁。", "success");
  } catch (error) { $("#connectionDot").classList.remove("connected"); setStatus(status, error.message, "error"); }
  finally { button.disabled = false; }
});

$("#refreshButton").addEventListener("click", async () => {
  try { await loadShares(); } catch (error) { setStatus($("#connectionStatus"), error.message, "error"); }
});

$("#shareForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("#fileInput").files?.[0], status = $("#uploadStatus"), button = $("#createShareButton");
  if (!file) return;
  try {
    const entries = readRecipients(), token = adminToken(); apiBase();
    button.disabled = true; $("#results").classList.add("hidden"); $("#resultList").replaceChildren();
    setStatus(status, "正在加密檔案並建立個別權限…");
    const result = await createShare(file, entries, token, status);
    let localLabels = {};
    try { localLabels = JSON.parse(localStorage.getItem(labelsKey) || "{}"); } catch {}
    localLabels[result.shareId] = file.name;
    localStorage.setItem(labelsKey, JSON.stringify(localLabels));
    result.items.forEach(addResult); $("#results").classList.remove("hidden");
    recipientsRoot.querySelectorAll(".recipient-password").forEach((input) => { input.value = ""; });
    setStatus(status, "加密分享已完成。", "success");
    await loadShares().catch((error) => setStatus($("#connectionStatus"), `分享已完成，但清單更新失敗：${error.message}`, "error"));
  } catch (error) {
    setStatus(status, error.message || "建立分享失敗。", "error");
  } finally { button.disabled = false; button.textContent = "加密並建立分享"; }
});

addRecipient();
