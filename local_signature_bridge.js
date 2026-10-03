/**
 * SignCore 64 - 本機簽章橋接微服務 (Local Signature Bridge)
 *
 * 與 mock_signature_server.js 的差異：
 *   mock 伺服器每次啟動生成「拋棄式」隨機金鑰，僅供 C 測試客戶端連通性測試；
 *   本 bridge 載入「與 ed25519_cryptographic_signature_service_platform.html 頁面
 *   同一把」的固定私鑰 —— 由頁面「匯出私鑰 → PKCS#8 PEM (ed25519-private.key)」
 *   下載取得。如此 sign_client_test.exe 對 bridge 簽出的資料，與頁面工作台
 *   簽出的簽章使用同一把 Ed25519 金鑰，可互相驗證，實現「頁面當金鑰持有者、
 *   外部程式當簽章消費者」的整合場景。
 *
 * 用法（埠與金鑰路徑可任意順序，亦可僅提供其一）：
 *   node local_signature_bridge.js [Port] [ed25519-private.key 路徑]
 *
 * 範例：
 *   node local_signature_bridge.js
 *   node local_signature_bridge.js 8090 ed25519-private.key
 *   node local_signature_bridge.js my-key.pem 9000
 *
 * 安全須知（與 mock 伺服器相同，本檔案屬測試/示範用途）：
 *   - 僅綁 127.0.0.1
 *   - PEM 為明文私鑰，勿放置於公開可讀路徑或提交至版本庫
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// 參數解析：相容三種呼叫形式，避免「僅傳金鑰路徑」被誤當埠號後遭忽略
//   node local_signature_bridge.js                      → 8090 + 預設金鑰
//   node local_signature_bridge.js 9000                 → 9000 + 預設金鑰
//   node local_signature_bridge.js my-key.pem           → 8090 + my-key.pem
//   node local_signature_bridge.js 9000 my-key.pem      → 9000 + my-key.pem
//   node local_signature_bridge.js my-key.pem 9000      → 9000 + my-key.pem
const DEFAULT_PORT = 8090;
const DEFAULT_KEY_PATH = path.join(__dirname, 'ed25519-private.key');
const isValidPort = (v) => { const n = parseInt(v, 10); return Number.isInteger(n) && n > 0 && n <= 65535 && String(n) === String(v).trim(); };
let PORT = DEFAULT_PORT;
let KEY_PATH = DEFAULT_KEY_PATH;
if (process.argv[2]) {
    if (isValidPort(process.argv[2])) {
        PORT = parseInt(process.argv[2], 10);
        if (process.argv[3]) KEY_PATH = process.argv[3];
    } else {
        KEY_PATH = process.argv[2];
        if (process.argv[3] && isValidPort(process.argv[3])) PORT = parseInt(process.argv[3], 10);
    }
}
const HOST = '127.0.0.1';
const MAX_BODY_BYTES = 1024 * 1024; // 1MB 請求體上限

// 1. 載入頁面匯出之 PKCS#8 PEM 私鑰 (ed25519-private.key)
console.log('正在載入頁面匯出的 Ed25519 固定私鑰...');
console.log(`   金鑰檔: ${KEY_PATH}`);

let privateKey;
try {
    if (!fs.existsSync(KEY_PATH)) {
        console.error('[錯誤] 找不到金鑰檔。請先在 SignCore 64 頁面：');
        console.error('       匯出私鑰 → PKCS#8 PEM → 下載 ed25519-private.key，');
        console.error('       或執行時指定路徑：node local_signature_bridge.js 8090 <金鑰路徑>');
        process.exit(1);
    }
    const pemText = fs.readFileSync(KEY_PATH, 'utf-8');
    privateKey = crypto.createPrivateKey(pemText);
    if (privateKey.asymmetricKeyType !== 'ed25519') {
        console.error('[錯誤] 金鑰檔不是 Ed25519 私鑰 (實際: ' + privateKey.asymmetricKeyType + ')');
        process.exit(1);
    }
} catch (err) {
    console.error('[錯誤] 金鑰檔載入/解析失敗:', err.message);
    process.exit(1);
}

// 衍生對應公鑰，取得 32-Byte Raw Public Key
const publicKey = crypto.createPublicKey(privateKey);
const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
const PUBLIC_KEY_HEX = rawPub.toString('hex');
console.log(`[BRIDGE ONLINE] 與頁面共用的公鑰 (32 Bytes): ${PUBLIC_KEY_HEX}`);

//進程結束時保證不把金鑰寫回磁碟 (privateKey 僅存在記憶體中)

// 2. 建立 HTTP API 伺服器 (端點邏輯與 mock_signature_server.js 完全一致)
const server = http.createServer((req, res) => {
    // 設置 CORS 與 JSON Header (允許頁面/其他本機工具呼叫)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host}`);

    // 端點 1: GET /api/v1/crypto/public-key
    if (req.method === 'GET' && parsedUrl.pathname === '/api/v1/crypto/public-key') {
        const responseData = {
            code: 200,
            status: 'SUCCESS',
            algorithm: 'Ed25519',
            public_key_hex: PUBLIC_KEY_HEX,
            key_byte_length: 32,
            timestamp: Math.floor(Date.now() / 1000)
        };
        res.writeHead(200);
        res.end(JSON.stringify(responseData, null, 2));
        console.log(`[GET 200] 查詢公鑰 -> ${PUBLIC_KEY_HEX}`);
        return;
    }

    // 端點 2: POST /api/v1/crypto/sign
    if (req.method === 'POST' && parsedUrl.pathname === '/api/v1/crypto/sign') {
        // 以 Buffer 收集、結束時一次解碼：避免多位元組 UTF-8 字元跨 chunk 邊界被截斷
        const chunks = [];
        let totalBytes = 0;
        let tooLarge = false;
        req.on('data', chunk => {
            if (tooLarge) return;
            chunks.push(chunk);
            totalBytes += chunk.length;
            if (totalBytes > MAX_BODY_BYTES) {
                tooLarge = true;
                res.writeHead(413);
                res.end(JSON.stringify({ code: 413, error: '請求 Payload 超過大小上限 (1MB)' }));
                req.destroy();
            }
        });
        req.on('end', () => {
            if (tooLarge) return;
            try {
                const reqJson = JSON.parse(Buffer.concat(chunks).toString('utf8'));
                const payload = reqJson.payload;

                if (typeof payload !== 'string') {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'payload 欄位為必填字串' }));
                    return;
                }

                // PureEd25519 直接簽署原始 Payload 位元組
                const dataBuffer = Buffer.from(payload, 'utf-8');
                const sigBuffer = crypto.sign(null, dataBuffer, privateKey);

                if (sigBuffer.length !== 64) {
                    throw new Error(`簽章長度非 64 位元組 (實際: ${sigBuffer.length})`);
                }

                const sigHex = sigBuffer.toString('hex');
                const sigB64 = sigBuffer.toString('base64');
                const hashHex = crypto.createHash('sha256').update(dataBuffer).digest('hex');

                const responseData = {
                    code: 200,
                    status: 'SUCCESS',
                    algorithm: 'Ed25519',
                    signature_byte_length: 64,
                    signature_hex: sigHex,
                    signature_base64: sigB64,
                    public_key_hex: PUBLIC_KEY_HEX,
                    payload_sha256: hashHex,
                    timestamp: Math.floor(Date.now() / 1000)
                };

                res.writeHead(200);
                res.end(JSON.stringify(responseData, null, 2));
                console.log(`[POST 200] 簽章生成成功 (Payload 長度: ${dataBuffer.length} bytes, 簽名: ${sigHex.substring(0, 16)}...)`);
            } catch (err) {
                res.writeHead(400);
                res.end(JSON.stringify({ code: 400, error: err.message }));
                console.error('[POST 400] 請求處理失敗:', err.message);
            }
        });
        return;
    }

    // 端點 3: POST /api/v1/crypto/verify (供測試程式校驗，預設驗證本 bridge 金鑰)
    if (req.method === 'POST' && parsedUrl.pathname === '/api/v1/crypto/verify') {
        const chunks = [];
        let totalBytes = 0;
        let tooLarge = false;
        req.on('data', chunk => {
            if (tooLarge) return;
            chunks.push(chunk);
            totalBytes += chunk.length;
            if (totalBytes > MAX_BODY_BYTES) {
                tooLarge = true;
                res.writeHead(413);
                res.end(JSON.stringify({ code: 413, error: '請求 Payload 超過大小上限 (1MB)' }));
                req.destroy();
            }
        });
        req.on('end', () => {
            if (tooLarge) return;
            try {
                const reqJson = JSON.parse(Buffer.concat(chunks).toString('utf8'));
                const payload = reqJson.payload;
                const sigHex = reqJson.signature_hex;
                const pubHex = reqJson.public_key_hex || PUBLIC_KEY_HEX;

                // 欄位格式前置校驗：給呼叫端比底層 OpenSSL 錯誤更可讀的 400 訊息
                if (typeof payload !== 'string') {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'payload 欄位為必填字串', valid: false }));
                    return;
                }
                if (typeof sigHex !== 'string' || sigHex.length !== 128 || /[^0-9a-fA-F]/.test(sigHex)) {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'signature_hex 格式不正確 (應為 128 字元 Hex = 64 Bytes)', valid: false }));
                    return;
                }
                if (typeof pubHex !== 'string' || pubHex.length !== 64 || /[^0-9a-fA-F]/.test(pubHex)) {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'public_key_hex 格式不正確 (應為 64 字元 Hex = 32 Bytes)', valid: false }));
                    return;
                }

                const dataBuffer = Buffer.from(payload, 'utf-8');
                const sigBuffer = Buffer.from(sigHex, 'hex');
                const pubBuffer = Buffer.from(pubHex, 'hex');

                // 組合 Ed25519 SPKI DER 標頭 (12 bytes)
                const spkiHeader = Buffer.from('302a300506032b6570032100', 'hex');
                const verifierKey = crypto.createPublicKey({
                    key: Buffer.concat([spkiHeader, pubBuffer]),
                    format: 'der',
                    type: 'spki'
                });

                const isValid = crypto.verify(null, dataBuffer, verifierKey, sigBuffer);

                res.writeHead(200);
                res.end(JSON.stringify({
                    code: 200,
                    status: 'SUCCESS',
                    valid: isValid,
                    message: isValid ? '簽章驗證通過' : '簽章無效'
                }, null, 2));
                console.log(`[POST 200] 驗證結果 -> ${isValid ? 'VALID ✓' : 'INVALID ✗'}`);
            } catch (err) {
                res.writeHead(400);
                res.end(JSON.stringify({ code: 400, error: err.message, valid: false }));
            }
        });
        return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ code: 404, error: '端點不存在' }));
});

server.listen(PORT, HOST, () => {
    console.log(`====================================================`);
    console.log(`SignCore 64 本機簽章橋接服務已啟動: http://${HOST}:${PORT}`);
    console.log(`- 取得公鑰: GET  http://${HOST}:${PORT}/api/v1/crypto/public-key`);
    console.log(`- 資料簽名: POST http://${HOST}:${PORT}/api/v1/crypto/sign`);
    console.log(`- 簽章驗證: POST http://${HOST}:${PORT}/api/v1/crypto/verify`);
    console.log(`本服務與瀏覽器頁面 ed25519_cryptographic_signature_service_platform.html`);
    console.log(`共享同一把私鑰 (由頁面匯出之 PKCS#8 PEM 載入)。`);
    console.log(`====================================================`);
});
