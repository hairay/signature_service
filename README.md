# SignCore 64 - Ed25519 密碼學簽章微服務架構與互動示範平台

[![Ed25519](https://img.shields.io/badge/Algorithm-Ed25519-indigo.svg)](https://datatracker.ietf.org/doc/html/rfc8032)
[![AES-256-GCM](https://img.shields.io/badge/Key_Encryption-AES--256--GCM-emerald.svg)](https://datatracker.ietf.org/doc/html/rfc5116)
[![WebCrypto API](https://img.shields.io/badge/WebCrypto-W3C_Standard-blue.svg)](https://www.w3.org/TR/WebCryptoAPI/)
[![Tests](https://img.shields.io/badge/E2E_Tests-4%2F4_Passing-brightgreen.svg)](#本機端對端自動化測試套件-test-kit)

SignCore 64 是一個輕量、免安裝、零建置依賴的 **Ed25519 密碼學數位簽章示範平台**。專案結合了**單檔案互動式瀏覽器應用**與**本機 C 語言 / Node.js 端對端自動化測試套件**，完整展示從金鑰安全生命週期（生成、靜態加密持久化、記憶體鎖定清零、匯出與匯入）到資料簽署、構造拆解與防竄改攔截驗證的全流程。

---

## 📌 核心架構與設計不變量 (Cryptographic Invariants)

1. **簽章長度核心不變量（精確 64 位元組 / 512 位元）**：
   - Ed25519 簽章標準表示為 $R \parallel S$：
     - **點 $R$（前 32 位元組 / 64 Hex 字元）**：簽署過程中隨機數與橢圓曲線基點標量乘法得到的臨時曲線點壓縮編碼。
     - **純量 $S$（後 32 位元組 / 64 Hex 字元）**：透過雜湊計算得出的純量值。
   - 格式相容 128 字元十六進位（Hex）與 88 字元 Base64（含補位）。
2. **公開金鑰不變量（精確 32 位元組 / 256 位元）**：
   - 固定 32 位元組壓縮格式（64 Hex 字元），相容標準 RFC 8410 SPKI DER 編碼（加附 12-byte 前綴）。
3. **本機私鑰安全加密持久化 (At-Rest Encryption)**：
   - 瀏覽器端使用 **PBKDF2-SHA256 (100,000 次迭代)** 衍生密鑰，並以 **AES-256-GCM** 加密封裝。
   - **AAD 綁定驗證**：將公開金鑰與版本標頭綁定為 AAD（附加認證資料），防止替換公鑰的篡改攻擊。
   - **雙層本機持久化**：優先寫入瀏覽器 **OPFS**（Origin Private File System）私有金鑰檔案 `signcore-ed25519-key.json`，若環境受限則自動回退至 `localStorage` 鏡像。
4. **記憶體生命週期與清零 (Memory Zeroization)**：
   - 提供「鎖定私鑰」按鈕，觸發後立即釋放 `CryptoKey` 物件、對記憶體中的金鑰位元組陣列執行 `fill(0)` 清零，並清除 DOM 樹中的明文暫存。

---

## 🚀 快速使用指南

專案提供兩種主要的使用方式：
1. **瀏覽器單檔案互動平台**：直觀視覺化操作、檔案雜湊簽章、金鑰備份匯入匯出與防竄改實測。
2. **C 語言與本機微服務自動化測試套件**：驗證跨語言底層 Socket 請求、簽章不變量與端對端通訊。

---

### 方式 1：瀏覽器互動示範平台

> [!NOTE]
> 本應用為單一 HTML 檔案實作，無須 Node.js、npm 或任何前端構建工具。載入頁面時需保持連網以自 CDN 載入 Tailwind CSS 與 Lucide 圖標庫。

#### 1. 啟動方式
直接使用任一現代瀏覽器（Chrome、Edge、Safari、Firefox）開啟：
```text
ed25519_cryptographic_signature_service_platform.html
```

#### 2. 操作流程

##### 第一步：金鑰初始化與安全控制
- 頁面載入時會自動檢查 OPFS / localStorage 中的金鑰檔；若為首次執行將自動生成一組全新 Ed25519 金鑰對。
- **變更密碼**：系統預設密碼為展示用途之 `signcore-master-2026`，點擊「變更密碼」可自訂新密碼，以 AES-256-GCM 重新加密私鑰檔。
- **鎖定私鑰**：點擊「鎖定私鑰」可將私鑰自記憶體中清零，此時簽署功能將被安全阻斷；輸入密碼解鎖後方可恢復。

##### 第二步：資料簽署（簽章工作台）
1. 在「簽章工作台」輸入欲簽署的純文字資料、點選「範例 Payload (JSON)」或將本機檔案拖曳至檔案上傳區（自動計算 SHA-256 摘要）。
2. 點擊「**執行 Ed25519 數位簽章**」。
3. 觀察下方輸出結果：
   - 完整 64-Byte 簽名（Hex 128 字元與 Base64 格式）。
   - **內部構造拆解**：點 $R$（前 32 Bytes）與純量 $S$（後 32 Bytes）。

##### 第三步：簽章驗證與防竄改演練
1. 在簽章產出區點擊「**帶入驗證工具檢驗**」，系統會自動將當前公鑰、資料與簽章填入「獨立驗證工具」頁籤。
2. 點擊「**立即執行 Ed25519 簽章校驗**」，畫面將提示 `✓ 簽章驗證通過 (Valid Signature)`。
3. 點擊「**注入篡改資料 (Tamper Injection)**」按鈕，系統會在原始資料末尾加入非預期字元並再次驗證，畫面將立即轉為 `✗ 簽章無效 (Invalid Signature)`，具體展示密碼學的防竄改能力。

##### 第四步：金鑰匯出與匯入（備份還原）
- **匯出私鑰（需在解鎖狀態下）**：
  - **加密備份檔 (.json)**：以 AES-256-GCM 加密保護，可安全下載並於其他 SignCore 節點還原。
  - **PKCS#8 PEM (.key)**：標準 RFC 8410 Base64 DER 私鑰編碼，相容於 OpenSSL、Java、Go 等後端。
  - **原始 Hex 種子 (.hex)**：64 字元十六進位純文字（32 Bytes Raw Seed）。
- **匯入私鑰**：
  - 支援拖曳上傳檔案或直接貼上文字內容。
  - 具備自動格式偵測（SignCore v2 加密檔、舊版 v1、PKCS#8 PEM、Raw Hex）。
  - 匯入時會自動執行 `validateKeyPairIntegrity` 簽驗閉環校驗，確保公私鑰匹配無誤後再以 AES-256-GCM 加密落地。

---

### 方式 2：本機端對端自動化測試套件 (Test Kit)

專案內建一套獨立的 **C 語言測試客戶端** 與 **Node.js 模擬微服務**，用於模擬外部系統與 SignCore API 的整合流程。

#### 前置環境需求
- **Node.js**（v16 以上，用於執行原生 `mock_signature_server.js`，零 npm 依賴）。
- **GCC / MinGW**（用於編譯 `sign_client_test.c`，Windows 下使用 Winsock2，Linux/macOS 使用 POSIX Socket）。

#### 一鍵自動化測試 (推薦)

- **PowerShell**：
  ```powershell
  powershell -ExecutionPolicy Bypass -File run_test.ps1
  ```
  *(若 8080 連接埠已被占用，可指定其他連接埠：`.\run_test.ps1 -Port 9000`)*

- **Windows Batch (CMD)**：
  在檔案總管中雙擊 `run_test.bat`，或在命令提示字元中執行：
  ```cmd
  run_test.bat
  ```

#### 4 大自動化測試情境說明

```
========================================================
 SignCore 64 - C 語言 Ed25519 簽章與公鑰端對端測試
========================================================

[測試 1] 查詢伺服器內部固定 Ed25519 公鑰 (GET /api/v1/crypto/public-key)...
  -> 取得公鑰 (Hex): 64 hex chars (32 Bytes)
  ✓ [PASS] 成功取得系統 Ed25519 公鑰 (符合 32 Bytes 規範)

[測試 2] 傳送業務資料並請求簽章 (POST /api/v1/crypto/sign)...
  -> 取得數位簽名 (Hex): 128 hex chars (64 Bytes)
  -> 點 R (前 32 Bytes) / 純量 S (後 32 Bytes) 拆分校驗
  ✓ [PASS] 成功取得 Ed25519 簽章 (符合精確 64 Bytes 核心不變量)

[測試 3] 發送正向驗證請求 (POST /api/v1/crypto/verify)...
  ✓ [PASS] 簽章正向驗證通過 (Valid Signature：資料完整且由原伺服器簽署)

[測試 4] 注入竄改資料以測試安全攔截 (POST /api/v1/crypto/verify)...
  ✓ [PASS] 竄改資料成功被攔截 (Tamper Detection Passed：金額被竄改後簽章立即失效)

========================================================
 測試成果：全部 4 項測試通過！(100% SUCCESS)
========================================================
```

詳細測試說明與手動逐步測試方式請參閱 [README_TEST.md](README_TEST.md)。

#### 進階：與頁面共用同一把金鑰的本機橋接服務 (Bridge)

`sign_client_test.exe` 無法與瀏覽器頁面直接溝通（網頁沙盒無法監聽 TCP 埠）。`local_signature_bridge.js` 補上這一環：它載入**由頁面「匯出私鑰 → PKCS#8 PEM」下載的 `ed25519-private.key`**，並以相同的三端點 API 對外服務，使外部程式簽出的資料與瀏覽器頁面**共用同一把 Ed25519 金鑰**，簽章可互相驗證。

```powershell
# 1. 在頁面中匯出私鑰 → PKCS#8 PEM → 下載 ed25519-private.key（放於專案目錄）
# 2. 啟動橋接服務（預設埠 8090）
node local_signature_bridge.js 8090 ed25519-private.key
# 3. 外部程式即可呼叫 http://127.0.0.1:8090/api/v1/crypto/*
#    或用測試腳本驗證整條鏈路（Bridge 模式）：
.\run_test.ps1 -BridgeKey ed25519-private.key -Port 8090
```

> [!WARNING]
> `ed25519-private.key` 為明文私鑰，已列入 `.gitignore`，切勿提交至版本庫或外傳。bridge 與 mock server 同屬本機測試/示範用途（僅綁 127.0.0.1、無鑑權/Nonce/限流）。

---

## 📂 專案檔案清單

| 檔案名稱 | 說明 |
| :--- | :--- |
| [`ed25519_cryptographic_signature_service_platform.html`](ed25519_cryptographic_signature_service_platform.html) | **前端主應用**：單檔案 Ed25519 互動工作台、驗證工具與微服務架構規範頁面。 |
| [`sign_client_test.c`](sign_client_test.c) | **C 語言客戶端**：無第三方依賴的 HTTP / Socket 客戶端測試程式。 |
| [`mock_signature_server.js`](mock_signature_server.js) | **Node.js 模擬微服務**：實作 `/public-key`、`/sign` 與 `/verify` 端點之測試雙標（Test Double），每次啟動生成拋棄式金鑰。 |
| [`local_signature_bridge.js`](local_signature_bridge.js) | **本機簽章橋接服務**：載入頁面匯出的 PKCS#8 PEM 私鑰，讓外部程式與瀏覽器頁面共用同一把 Ed25519 金鑰。 |
| [`run_test.ps1`](run_test.ps1) | **PowerShell 一鍵測試腳本**：包含埠衝突檢測、伺服器啟動與 PID 精確回收。 |
| [`run_test.bat`](run_test.bat) | **Windows 批次檔**：雙擊即測的批次執行檔。 |
| [`README_TEST.md`](README_TEST.md) | 端對端測試套件專屬技術說明文件。 |
| [`AGENTS.md`](AGENTS.md) | AI Agent 與開發者設計準則、密碼學不變量規範與踩坑提醒。 |
| [`.gitignore`](.gitignore) | 排除編譯產出的二進位執行檔（如 `sign_client_test.exe`）。 |

---

## 🔐 生產環境落地的安全建議 (Production Best Practices)

- **金鑰保管**：本專案網頁端採用瀏覽器 OPFS + AES-256-GCM 進行展示性持久化。在真實生產微服務架構中，私鑰應保管於 **硬體安全模組 (HSM)** 或 **雲端密鑰管理服務 (Cloud KMS)**，私鑰絕不應接觸應用層記憶體或落地磁碟。
- **重放防護 (Replay Protection)**：生產簽署 API 應實施嚴格的 `nonce`（隨機數）唯一性校驗、時戳容許窗口（如 ±60 秒），並搭配雙向 TLS (mTLS) 與 API 權限存取控制。
- **演算法相容性**：現代瀏覽器皆完整支援 W3C WebCrypto API 之 Ed25519；若於不支援之舊式環境開啟，系統會自動切換為模擬演示模式並給予警示。

---

## 📄 授權條款

本專案採用 [MIT License](LICENSE) 授權。
