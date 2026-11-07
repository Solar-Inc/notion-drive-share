import { CHUNK_SIZE, MAX_CHUNKS, fromBase64Url, unwrapContentKey, decryptMetadata, decryptChunk } from "./crypto.js";

const $ = (selector) => document.querySelector(selector);
const params = new URLSearchParams(location.search);
const shareId = params.get("id") || "";
const token = new URLSearchParams(location.hash.slice(1)).get("t") || "";
let apiBase = "";
let access = null;
let contentKey = null;
let fileMetadata = null;

function setStatus(message, state = "") { const element = $("#status"); element.textContent = message; element.className = `status ${state}`.trim(); }
function formatBytes(value) { if (value < 1024) return `${value} B`; const units = ["KB", "MB", "GB", "TB"]; let size = value, index = -1; do { size /= 1024; index++; } while (size >= 1024 && index < units.length - 1); return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[index]}`; }

async function api(path) {
  const response = await fetch(`${apiBase}${path}`, { cache: "no-store", headers: { Authorization: `Bearer ${token}` } });
  const type = response.headers.get("content-type") || "";
  if (!response.ok) {
    const data = type.includes("application/json") ? await response.json().catch(() => null) : null;
    throw new Error(data?.error || (response.status === 404 || response.status === 403 ? "此分享連結無效、已撤銷或已到期。" : `讀取分享失敗（${response.status}）`));
  }
  return response;
}

async function loadLink() {
  if (!/^[a-f0-9-]{36}$/i.test(shareId) || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error("分享網址格式不完整，請向分享者索取正確網址。");
  const rawApi = params.get("api") || "";
  let parsed;
  try { parsed = new URL(rawApi); } catch { throw new Error("分享網址缺少儲存服務資訊。"); }
  if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") throw new Error("分享服務必須使用 HTTPS。");
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") throw new Error("分享服務網址無效。");
  apiBase = parsed.origin;
  const response = await api(`/api/share/${encodeURIComponent(shareId)}`);
  access = await response.json();
  if (access.id !== shareId || access.chunkSize !== CHUNK_SIZE || !Number.isSafeInteger(access.chunkCount) || access.chunkCount < 1 || access.chunkCount > MAX_CHUNKS)
    throw new Error("分享資料格式不支援。");
  $("#title").textContent = "這份檔案已加密保護";
  $("#description").textContent = "輸入分享者給你的個人密碼，即可在本機解密。密碼不會傳送到伺服器。";
  $("#unlockForm").classList.remove("hidden");
  setStatus("連結有效，等待密碼。", "success");
}

function renderPreview(blob) {
  const root = $("#preview"); root.replaceChildren();
  const url = URL.createObjectURL(blob);
  if (fileMetadata.mime.startsWith("image/")) {
    const image = document.createElement("img"); image.src = url; image.alt = fileMetadata.name; root.append(image);
  } else if (fileMetadata.mime.startsWith("video/")) {
    const video = document.createElement("video"); video.src = url; video.controls = true; video.playsInline = true; root.append(video);
  } else if (fileMetadata.mime.startsWith("audio/")) {
    const audio = document.createElement("audio"); audio.src = url; audio.controls = true; root.append(audio);
  } else if (fileMetadata.mime.startsWith("text/") || fileMetadata.mime === "application/json") {
    const pre = document.createElement("pre"); pre.textContent = blob.size <= 2 * 1024 * 1024 ? "" : "文字檔太大，請使用下載按鈕。";
    if (blob.size <= 2 * 1024 * 1024) blob.text().then((text) => { pre.textContent = text; });
    root.append(pre); URL.revokeObjectURL(url);
  } else {
    const note = document.createElement("p"); note.className = "empty"; note.textContent = "此檔案類型已解密，請下載後使用相容的應用程式開啟。"; root.append(note);
    URL.revokeObjectURL(url);
  }
  $("#saveButton").classList.remove("hidden");
  $("#saveButton").onclick = () => saveFile(blob);
}

function safeFilename(name) { return String(name || "shared-file").replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").slice(0, 180) || "shared-file"; }

async function saveFile(blob) {
  const filename = safeFilename(fileMetadata.name);
  if (window.showSaveFilePicker) {
    const handle = await window.showSaveFilePicker({ suggestedName: filename });
    const writable = await handle.createWritable(); await writable.write(blob); await writable.close();
    return;
  }
  const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = filename; link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 60000);
}

async function decryptSmallFile(rawKey) {
  const parts = [];
  for (let index = 0; index < access.chunkCount; index++) {
    const response = await api(`/api/share/${encodeURIComponent(shareId)}/chunks/${index}`);
    const cipher = new Uint8Array(await response.arrayBuffer());
    const plainSize = Math.min(CHUNK_SIZE, fileMetadata.size - index * CHUNK_SIZE);
    parts.push(await decryptChunk(cipher, rawKey, shareId, fromBase64Url(access.noncePrefix), index, plainSize));
    setStatus(`正在解密：${index + 1} / ${access.chunkCount} 個區塊`);
  }
  const blob = new Blob(parts, { type: fileMetadata.mime || "application/octet-stream" });
  if (blob.size !== fileMetadata.size) throw new Error("檔案大小驗證失敗。");
  renderPreview(blob);
  setStatus("解密完成；檔案只在此分頁記憶體中。", "success");
}

async function decryptLargeFile(rawKey) {
  if (!window.showSaveFilePicker) throw new Error("此檔案較大，請使用支援本機串流儲存的桌面 Chrome 或 Edge。");
  const handle = await window.showSaveFilePicker({ suggestedName: safeFilename(fileMetadata.name) });
  const writable = await handle.createWritable();
  try {
    for (let index = 0; index < access.chunkCount; index++) {
      const response = await api(`/api/share/${encodeURIComponent(shareId)}/chunks/${index}`);
      const cipher = new Uint8Array(await response.arrayBuffer());
      const plainSize = Math.min(CHUNK_SIZE, fileMetadata.size - index * CHUNK_SIZE);
      const plain = await decryptChunk(cipher, rawKey, shareId, fromBase64Url(access.noncePrefix), index, plainSize);
      await writable.write(plain);
      setStatus(`正在解密並儲存：${index + 1} / ${access.chunkCount} 個區塊`);
    }
    await writable.close();
  } catch (error) { await writable.abort().catch(() => {}); throw error; }
  setStatus("檔案已解密並儲存至你選擇的位置。", "success");
}

$("#unlockForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#unlockButton"); button.disabled = true;
  try {
    const password = $("#password").value;
    contentKey = await unwrapContentKey(access.envelope, password, shareId);
    fileMetadata = await decryptMetadata(access.metadata, contentKey, shareId);
    if (fileMetadata.size !== access.plaintextSize || Math.ceil(fileMetadata.size / CHUNK_SIZE) !== access.chunkCount)
      throw new Error("分享檔案大小與區塊數不一致。");
    $("#password").value = "";
    $("#fileName").textContent = fileMetadata.name;
    $("#fileSize").textContent = formatBytes(fileMetadata.size);
    $("#filePanel").classList.remove("hidden");
    if (fileMetadata.size > 128 * 1024 * 1024) {
      $("#saveButton").classList.remove("hidden");
      $("#saveButton").textContent = "解密並儲存大型檔案";
      $("#saveButton").onclick = () => decryptLargeFile(contentKey).catch((error) => setStatus(error.message, "error"));
      setStatus("密碼正確。大型檔案會直接解密到你選擇的位置，不會整份載入記憶體。", "success");
    } else {
      await decryptSmallFile(contentKey);
    }
  } catch (error) { setStatus(error.message || "無法解鎖分享。", "error"); }
  finally { button.disabled = false; }
});

loadLink().catch((error) => { $("#title").textContent = "無法開啟這份分享"; setStatus(error.message, "error"); });
