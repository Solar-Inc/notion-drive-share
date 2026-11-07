# Notion Drive Share

GitHub Pages 前端搭配 Cloudflare Worker 與 D1 權限索引，檔案密文直接以 Notion 頁面附件保存。管理者上傳檔案並為每位收件人設定不同密碼；收件人使用專屬網址和密碼在瀏覽器解密。

## Notion Drive 儲存方式

- Worker 在你指定的 Notion Drive 根頁面下，為每份分享建立一個 `NDSHARE1.<隨機 ID>` 子頁，再把加密區塊以 Notion 檔案附件附在該頁。
- 頁面標題、附件名稱只含隨機分享 ID 和區塊編號；檔名、MIME 類型和檔案內容都不以明文寫入 Notion。Notion 及 Worker 仍可見檔案大小、區塊數與管理者設定的收件人標籤。
- 這些 `NDSHARE1` 頁面是分享站的儲存記錄，不是 Notion Drive 目前 `NDP1` 加密檔案格式，因此不會出現在 Notion Drive 一般檔案清單中。既有 Vault 與原有檔案格式不變。
- Worker 需持有 Notion integration token 才能代收件人讀取密文；token 只放在 Cloudflare Worker Secret，不放進 GitHub、前端或分享網址。

## 加密與權限

- 檔案分成 4 MiB 區塊，在管理者瀏覽器以 AES-256-GCM 加密後才上傳到 Notion。
- 每份分享使用獨立隨機檔案金鑰。每位收件人的密碼各自經 PBKDF2-HMAC-SHA-256（600,000 次）衍生金鑰，再以 AES-GCM 封裝該檔案金鑰。
- 檔名與 MIME 類型以 AES-GCM 加密。D1 保存加密 metadata、Notion 頁面與區塊 ID、權限紀錄；Worker 可見檔案大小、區塊數和收件人標籤。
- 分享網址的隨機 Token 放在 `#` fragment，瀏覽器不會把 fragment 傳給 Worker；存取時由頁面放在 Authorization 標頭。密碼不會離開收件人的瀏覽器。
- 管理密鑰只在管理者目前分頁的 `sessionStorage`，不寫入程式碼或 GitHub；網址設定可保存在本機 `localStorage`。

這是以持有網址與密碼作為授權方式。它不驗證收件人的真實身分；收件人若把兩者轉交給別人，對方也能開啟。撤銷會阻止後續伺服器存取，無法收回已下載的明文副本。

## 部署

### 1. 建立 Notion integration

1. 在 Notion 建立內部 integration，授予讀取內容、插入內容與更新內容能力。
2. 將你的 Notion Drive 根頁面分享給該 integration，並確認它能在根頁面下建立子頁與檔案附件。
3. 複製 integration secret 和根頁面 ID。Token 只設定到 Cloudflare Worker Secret，不要貼進公開 repo 或分享站表單。

### 2. 建立 Cloudflare API

在 Cloudflare 建立一個 D1 database，將 `worker/wrangler.toml` 的 `database_id` 和 `NOTION_ROOT_PAGE_ID` 換成你的實際值，然後：

1. 安裝 Wrangler 並登入：`npm install --global wrangler`、`wrangler login`。
2. 在 `worker/` 執行 `wrangler d1 execute notiondrive-share --remote --file=schema.sql` 建立資料表。
3. 設定分享管理密鑰：`wrangler secret put ADMIN_TOKEN`，長度至少 32 個字元。
4. 設定 Notion integration secret：`wrangler secret put NOTION_TOKEN`。
5. 從 `worker/` 執行 `wrangler deploy`，記下 Worker 網址。

Worker 的 `ALLOWED_ORIGIN` 預設為 `https://solar-inc.github.io`。若 GitHub Pages 網址不同，請先修改該值再部署。自訂網域也必須填入正確的 origin（只含 scheme 與 hostname）。本架構不使用 R2；檔案密文直接儲存在 Notion Drive 根頁面下。

### 3. 使用分享站

管理頁位於 `https://solar-inc.github.io/notion-drive-share/`，收件人頁為同網址下的 `view.html`。管理頁填入 Worker 網址和 `ADMIN_TOKEN`。新增收件人時輸入名稱與至少 12 字元的唯一密碼；建議使用密碼管理器產生 16 個以上隨機字元。每人會得到不同的網址與密碼，請透過不同管道傳送。

管理頁會將分享檔名保留在這個瀏覽器的本機資料中，以便重新整理後辨識分享；伺服器不保存明文檔名。切換裝置時，分享清單會改用分享 ID 辨識。

## 驗證範圍

本機 Node 24 的 8 項測試涵蓋個別密碼、錯誤密碼、金鑰綁定、檔案與區塊改動、未完成上傳、個別撤銷、整份撤銷，以及 Notion 頁面清理失敗時停止存取。Notion API 使用本機模擬服務；尚未在你的 Notion integration 或 Cloudflare D1 帳號執行端到端驗收。

在專案根目錄可執行：`node --test share/tests/crypto.test.mjs worker/tests/api.test.mjs`。

## 限制

- 單份分享最多約 39.06 GiB（41,943,040,000 bytes）、10,000 個區塊、30 位收件人。實際可用容量仍受 Notion 工作區上傳與儲存限制、API 限流影響。
- 128 MiB 以下可在瀏覽器記憶體預覽；較大的檔案會解密至收件人選取的位置，需要支援 File System Access API 的桌面 Chrome 或 Edge。
- 密碼封裝可離線猜測；短密碼容易被猜中。使用高熵、每位收件人不同的密碼。
- 靜態前端由 GitHub Pages 提供；Cloudflare D1/Worker 與 Notion integration 需要依照上方步驟另行設定。此 repo 不含任何 Notion Token 或 Worker 管理密鑰。
