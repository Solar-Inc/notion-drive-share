# Notion Drive Share

以 Notion Drive 的深色介面與 Notion 儲存空間為基礎建立的獨立加密分享站。

管理者上傳檔案並指定收件人；每位收件人有獨立網址與密碼。檔案在瀏覽器端加密後，密文以 Notion 頁面附件保存。管理者可逐人撤銷存取。

網站前端：https://solar-inc.github.io/notion-drive-share/

完整原始碼與測試位於 `share/` 與 `worker/`。部署步驟與安全邊界見 `share/README.md`。

## 目前狀態

- 管理者頁、收件人頁、端對端加密與個別權限 API 已實作。
- 本機 8 項加密與 API 測試通過；API 測試使用 SQLite 和 Notion API 模擬服務。
- GitHub Actions 發佈靜態前端。真正跨裝置上傳與分享需要部署 Cloudflare Worker、D1，並授權 Notion integration 存取你的 Notion Drive 根頁面。
- 尚未在真實 Notion integration 或 Cloudflare 帳號完成端到端驗收。

檔案明文、密碼與檔案金鑰不會上傳。持有網址與密碼者即可讀取；收件人若轉交兩者，對方也能開啟。撤銷會阻止後續伺服器存取，已下載的副本無法收回。
