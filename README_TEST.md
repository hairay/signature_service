# SignCore 64 - C 語言端對端簽章測試程式說明

本測試套件提供完整的 **C 語言客戶端** 與符合 SignCore 64 規格的 **本機微服務模擬伺服器**，用於驗證向微服務傳送資料、取得 64-Byte Ed25519 簽章與 32-Byte 公鑰，並驗證簽章完整性與防竄改機制。

---

## 檔案清單

| 檔案名稱 | 角色與用途 |
| :--- | :--- |
| `sign_client_test.c` | **C 語言測試客戶端**：零第三方函式庫依賴（Windows 使用 Winsock，Linux/macOS 使用 POSIX Socket），負責發送 HTTP GET/POST、解析 JSON 取得 64-byte 簽章、分解 R/S 分量與驗證。 |
| `mock_signature_server.js` | **本機模擬微服務**：純 Node.js 原生實作（零 npm 依賴），提供 `GET /api/v1/crypto/public-key`、`POST /api/v1/crypto/sign` 與 `POST /api/v1/crypto/verify` 端點。 |
| `run_test.ps1` | **PowerShell 一鍵自動化測試腳本**：自動編譯 C 程式、啟動背景伺服器、執行 4 項測試並於結束後自動清理關閉。 |
| `run_test.bat` | **Windows CMD 一鍵測試批次檔**。 |

---

## 4 大測試情境

1. **[測試 1] 系統公鑰查詢 (`GET /api/v1/crypto/public-key`)**
   - 驗證是否能成功取得 32 位元組（64 Hex 字元）之 Ed25519 系統固定公鑰。
2. **[測試 2] 傳送資料並取得 64-Byte 簽章 (`POST /api/v1/crypto/sign`)**
   - 傳送業務交易 JSON Payload。
   - 檢驗簽章是否符合核心不變量（精確 64 位元組 / 128 Hex 字元 / Base64 格式）。
   - 解析並拆解 Ed25519 內部構造：**點 $R$ (前 32 Bytes)** 與 **純量 $S$ (後 32 Bytes)**。
3. **[測試 3] 正向簽章真偽校驗 (`POST /api/v1/crypto/verify`)**
   - 傳送原始資料、公鑰與剛剛取得的簽章，確認回傳 `valid: true`（資料完整且由原私鑰簽發）。
4. **[測試 4] 竄改攔截安全測試 (`POST /api/v1/crypto/verify`)**
   - 將交易金額由 `12500` 竄改為 `99999`，搭配原簽名再次送驗，確認回傳 `valid: false`（證明微小竄改即會被密碼學機制安全攔截）。

---

## 快速執行方式

### 方式 1：一鍵自動化測試 (推薦)

在終端機（PowerShell）中直接執行：
```powershell
.\run_test.ps1
```
或在 Windows 檔案總管中雙擊：
```cmd
run_test.bat
```

### 方式 2：手動分步編譯與執行

1. **啟動模擬伺服器**：
   ```bash
   node mock_signature_server.js
   ```

2. **編譯 C 語言客戶端**：
   - **Windows** (GCC / MinGW):
     ```bash
     gcc -o sign_client_test.exe sign_client_test.c -lws2_32
     ```
   - **Linux / macOS**:
     ```bash
     gcc -o sign_client_test sign_client_test.c
     ```

3. **執行測試客戶端**：
   ```bash
   # 語法: ./sign_client_test [主機IP] [連接埠]
   .\sign_client_test.exe 127.0.0.1 8080
   ```
