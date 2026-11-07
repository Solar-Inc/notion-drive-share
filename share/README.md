# Notion Drive Share

GitHub Pages 靜態分享站，加上 Cloudflare Worker、D1 與 R2 儲存 API。管理者在瀏覽器上傳檔案，為每位收件人設定不同密碼；收件人使用專屬網址和密碼在瀏覽器解密。

## 加密與權限

- 檔案分成 4 MiB 區塊，在管理者瀏覽器以 AES-256-GCM 加密後才上傳。
- 每份分享使用獨立隨機檔案金鑰。每位收件人的密碼各自經 PBKDF2-HMAC-SHA-256（600,000 次）衍生金鑰，再以 AES-GCM 封裝該檔案金鑰。
- 檔名與 MIME 類型以 AES-GCM 加密。Worker 可見檔案大小、區塊數和收件人標籤，並保存檔案密文、密碼封裝和隨機連結 Token 的 SHA-256 雜湊。
- 分享網址的隨機 Token 放在 `#` fragment，瀏覽器不會把 fragment 傳給 Worker；存取時由頁面放在 Authorization 標頭。密碼不會離開收件人的瀏覽器。
- 管理密鑰只在管理者目前分頁的 `sessionStorage`，不寫入程式碼或 GitHub；網址設定可保存在本機 `localStorage`。

這是以持有網址與密碼作為授權方式。它不驗證收件人的真實身分；收件人若把兩者轉交給別人，對方也能開啟。撤銷會阻止後續伺服器存取，無法收回已下載的明文副本。

## 部署

### 1. 建立儲存 API

在 Cloudflare 建立一個 R2 bucket 和一個 D1 database，然後：

1. 將 `worker/wrangler.toml` 的 `database_id` 換成 D1 資料庫 ID。確認 `bucket_name` 與你建立的 R2 bucket 名稱相同。
2. 安裝 Wrangler 並登入：`npm install --global wrangler`、`wrangler login`。
3. 在 `worker/` 執行 `wrangler d1 execute notiondrive-share --remote --file=schema.sql` 建立資料表。
4. 設定長度至少 32 位元組的管理密鑰：`wrangler secret put ADMIN_TOKEN`。
5. 從 `worker/` 執行 `wrangler deploy`，記下 Worker 網址。

Worker 的 `ALLOWED_ORIGIN` 預設為 `https://solar-inc.github.io`。若 GitHub Pages 網址不同，請先修改該值再部署。自訂網域也必須填入正確的 origin（只含 scheme 與 hostname）。

### 2. 發佈 GitHub Pages 前端

這是獨立專案 `Solar-Inc/notion-drive-share`。Pages workflow 會先執行測試，再把 `share/` 目錄發佈為網站根目錄。管理頁會在 `https://solar-inc.github.io/notion-drive-share/`，收件人頁為同網址下的 `view.html`。

管理頁填入 Worker 網址和 `ADMIN_TOKEN`。管理密鑰只保留在目前分頁。新增收件人時輸入名稱與至少 12 字元的唯一密碼；建議使用密碼管理器產生 16 個以上隨機字元。每人會得到不同的網址和密碼。請透過不同管道傳送網址與密碼。

管理頁會將分享檔名保留在這個瀏覽器的本機資料中，以便重新整理後辨識分享；伺服器不保存明文檔名。切換裝置時，分享清單會改用分享 ID 辨識。

## 驗證範圍

本機 Node 24 的 8 項測試通過，包含個別密碼、錯誤密碼、金鑰綁定、檔案與區塊改動、未完成上傳、個別撤銷、整份撤銷，以及儲存區清理失敗後停止存取。API 測試使用 SQLite 與模擬 R2；尚未在真實 Cloudflare D1/R2 帳號進行端到端驗收。

在專案根目錄可執行：`node --test share/tests/crypto.test.mjs worker/tests/api.test.mjs`。

## 限制

- 單份分享最多約 39.06 GiB（41,943,040,000 bytes）、10,000 個區塊、30 位收件人。Worker 以 4 MiB 區塊順序傳輸。
- 128 MiB 以下可在瀏覽器記憶體預覽；較大的檔案會解密至收件人選取的位置，需要支援 File System Access API 的桌面 Chrome 或 Edge。
- 密碼封裝可離線猜測；短密碼容易被猜中。使用高熵、每位收件人不同的密碼。
- 靜態前端由 GitHub Pages 提供；Cloudflare D1/R2/Worker 需要依照上方步驟另行建立並部署。此 repo 不含任何 Token 或 Worker 管理密鑰。
