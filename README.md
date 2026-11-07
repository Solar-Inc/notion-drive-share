# Notion Drive Share

以 Notion Drive 的深色介面為模板建立的獨立加密分享站。

管理者上傳檔案並指定收件人；每位收件人有獨立網址與密碼。收件人以密碼在瀏覽器解密檢視檔案。管理者可逐人撤銷存取，或撤銷整份分享。

網站前端：https://solar-inc.github.io/notion-drive-share/

完整原始碼與 8 項測試位於 `share/` 與 `worker/`。部署前先閱讀 `share/README.md`。

## 目前狀態

- 管理者頁、收件人頁、加密與權限 API 已實作。
- 本機 8 項加密與 API 測試通過；API 測試使用 SQLite 和模擬 R2。
- GitHub Actions 會發佈靜態前端。真正跨裝置上傳與分享，需要另外部署`worker/` 中的 Cloudflare Worker、D1 和 R2，並設定管理密鑰。
- 本專案尚未完成真實 Cloudflare 帳號的端到端驗收，不應視為已完成正式營運部署。

檔案明文、密碼與檔案金鑰不會上傳。持有網址與密碼者即可讀取；收件人若轉交兩者，對方也能開啟。撤銷會阻止後續伺服器存取，已下載的副本無法收回。
