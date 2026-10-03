/**
 * SignCore 64 - 遠端 Ed25519 密碼學簽章微服務 (Remote Cryptographic Signature Service)
 *
 * 核心特色：
 * 1. 遠端開放監聽：預設綁定 0.0.0.0，使區網或遠端 Client 皆能連線取得公鑰與資料簽章。
 * 2. 嚴格不變量遵循：公鑰精確 32 位元組 (64 Hex)，簽章精確 64 位元組 (128 Hex，R‖S 分割)。
 * 3. 金鑰來源與生命週期：
 *    - 支援從環境變數 (ED25519_PRIVATE_KEY_PEM) 直接載入，避免磁碟遺留明文。
 *    - 支援本地 PKCS#8 PEM 載入或自動生成臨時金鑰。
 *    - 退出信號攔截 (SIGINT / SIGTERM)：關閉伺服器、釋放金鑰引用並結束進程
 *      (JS 層無法保證清零 V8 內部 KeyObject 緩衝區，實際回收交由 GC 與進程結束)。
 *    - Core Dump 防護屬作業系統層職責 (systemd NoDump / 容器 / ulimit -c 0)。
 *    - 支援 API Key 鑑別 (SIGNCORE_API_KEY)，防止未授權端點將此服務當作簽名神諭 (Signing Oracle)。
 *    - 鑑權使用常數時間比對 (crypto.timingSafeEqual)，抵禦時序攻擊 (Timing Attack)。
 * 4. 零外部 npm 依賴：全原生 Node.js (http + crypto)。
 *
 * 安全警告：
 *   本服務為明文 HTTP 且預設 0.0.0.0 對外監聽，X-Api-Key 會以明文標頭過網。
 *   僅限受信任內網使用；跨不受信任網路部署時，務必置於 TLS 反向代理 (HTTPS/mTLS) 之後。
 *
 * 參數解析規則（順序無關，依形式判別；自訂主機名請用環境變數 SIGNCORE_HOST）：
 *   - 純數字 1-65535             → 埠號
 *   - localhost 或 IPv4 位址     → 監聽位址
 *   - 其他 (含 .pem/.key 檔名)   → 私鑰檔路徑
 *
 * 用法：
 *   node remote_signature_service.js [Port] [金鑰路徑 | Host]
 *
 * 範例：
 *   node remote_signature_service.js                          → 8090 埠, 0.0.0.0 監聽, 載入預設金鑰
 *   node remote_signature_service.js 9000                     → 9000 埠, 0.0.0.0 監聽
 *   node remote_signature_service.js 8090 ed25519-private.key → 指定金鑰檔路徑
 *   node remote_signature_service.js 8090 127.0.0.1           → 僅本機監聽 (載入預設金鑰)
 *   SIGNCORE_HOST=myhost.lan node remote_signature_service.js → 以主機名監聽
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ==========================================
// 1. 參數解析與環境變數設定
// ==========================================
const DEFAULT_PORT = parseInt(process.env.SIGNCORE_PORT || process.env.PORT || '8090', 10);
const DEFAULT_HOST = process.env.SIGNCORE_HOST || '0.0.0.0';
const DEFAULT_KEY_PATH = path.join(__dirname, 'ed25519-private.key');
const API_KEY = process.env.SIGNCORE_API_KEY || ''; // 若留空則不強制認證（開發測試模式）
const MAX_BODY_BYTES = 1024 * 1024; // 1MB 請求體上限

const isValidPort = (v) => {
    const n = parseInt(v, 10);
    return Number.isInteger(n) && n > 0 && n <= 65535 && String(n) === String(v).trim();
};

let PORT = DEFAULT_PORT;
let HOST = DEFAULT_HOST;
let KEY_PATH = DEFAULT_KEY_PATH;
let userKeyPathSpecified = false;

// 命令列參數解析 (埠號 / localhost|IPv4 / 金鑰路徑，順序無關)
// 注意：僅 localhost 與合法 IPv4 會被視為位址——含點的檔名 (如 .pem/.key) 必須落進金鑰路徑，
// 否則會被拿去當 HOST 做 DNS 解析而直接 crash
const isIPv4Arg = (v) => {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
    return !!m && m.slice(1).every(o => Number(o) <= 255);
};
const isHostArg = (v) => v === 'localhost' || isIPv4Arg(v);
const args = process.argv.slice(2);
for (const arg of args) {
    if (isValidPort(arg)) {
        PORT = parseInt(arg, 10);
    } else if (isHostArg(arg)) {
        HOST = arg;
    } else {
        KEY_PATH = arg;
        userKeyPathSpecified = true;
    }
}

// 常數時間 API Key 校驗：預先計算 SHA-256 雜湊再比對，防範時序攻擊 (Timing Attack) 與長度洩漏
function verifyApiKey(clientAuth, expectedKey) {
    if (!expectedKey) return true;
    if (!clientAuth) return false;
    const token = clientAuth.replace(/^Bearer\s+/i, '').trim();
    if (!token) return false;
    const hashA = crypto.createHash('sha256').update(token, 'utf-8').digest();
    const hashB = crypto.createHash('sha256').update(expectedKey, 'utf-8').digest();
    return crypto.timingSafeEqual(hashA, hashB);
}

// ==========================================
// 2. 私鑰載入與公鑰衍生 (Key Management)
// ==========================================
let privateKey = null;
let rawPublicKeyBuffer = null;
let PUBLIC_KEY_HEX = '';
let keySourceDesc = '';

function initKeyPair() {
    // 優先順序 A: 環境變數注入 (最安全，不經磁碟)
    if (process.env.ED25519_PRIVATE_KEY_PEM) {
        try {
            privateKey = crypto.createPrivateKey(process.env.ED25519_PRIVATE_KEY_PEM);
            keySourceDesc = '環境變數 (ED25519_PRIVATE_KEY_PEM)';
        } catch (err) {
            console.error('[錯誤] 解析環境變數 ED25519_PRIVATE_KEY_PEM 失敗:', err.message);
            process.exit(1);
        }
    }
    // 優先順序 B-1: 使用者命令列顯式指定之 PKCS#8 PEM 檔案 (若不存在必須報錯，禁止靜默降級)
    else if (userKeyPathSpecified) {
        if (!fs.existsSync(KEY_PATH)) {
            console.error(`[錯誤] 指定的金鑰檔案不存在: ${path.resolve(KEY_PATH)}`);
            process.exit(1);
        }
        try {
            const pemText = fs.readFileSync(KEY_PATH, 'utf-8');
            privateKey = crypto.createPrivateKey(pemText);
            keySourceDesc = `使用者指定本地金鑰檔 (${path.resolve(KEY_PATH)})`;
        } catch (err) {
            console.error(`[錯誤] 載入金鑰檔 ${KEY_PATH} 失敗:`, err.message);
            process.exit(1);
        }
    }
    // 優先順序 B-2: 預設本地 PKCS#8 PEM 檔案存在
    else if (fs.existsSync(KEY_PATH)) {
        try {
            const pemText = fs.readFileSync(KEY_PATH, 'utf-8');
            privateKey = crypto.createPrivateKey(pemText);
            keySourceDesc = `預設本地金鑰檔 (${path.resolve(KEY_PATH)})`;
        } catch (err) {
            console.error(`[錯誤] 載入預設金鑰檔 ${KEY_PATH} 失敗:`, err.message);
            process.exit(1);
        }
    }
    // 優先順序 C: 自動生成本次進程專用拋棄式金鑰 (僅在未顯式指定且無預設檔時啟用)
    else {
        const pair = crypto.generateKeyPairSync('ed25519');
        privateKey = pair.privateKey;
        keySourceDesc = '記憶體動態生成拋棄式金鑰 (重啟後失效)';
    }

    if (privateKey.asymmetricKeyType !== 'ed25519') {
        console.error(`[錯誤] 載入之金鑰非 Ed25519 演算法 (實際為: ${privateKey.asymmetricKeyType})`);
        process.exit(1);
    }

    // 衍生 32-Byte Raw Public Key (RFC 8410 SPKI DER 前綴為 12 bytes: 302a300506032b6570032100)
    const pubObj = crypto.createPublicKey(privateKey);
    rawPublicKeyBuffer = pubObj.export({ type: 'spki', format: 'der' }).subarray(12);
    PUBLIC_KEY_HEX = rawPublicKeyBuffer.toString('hex');

    // 啟動自我驗證 (Self-test)：閉環簽名與校驗，斷言金鑰健全性與 32-Byte 公鑰 / 64-Byte 簽章不變量
    try {
        const selftestData = Buffer.from('signcore-selftest-probe', 'utf-8');
        const selftestSig = crypto.sign(null, selftestData, privateKey);
        const isValidSelf = crypto.verify(null, selftestData, pubObj, selftestSig);
        if (!isValidSelf || rawPublicKeyBuffer.length !== 32 || selftestSig.length !== 64) {
            throw new Error(`自我驗證不通過 (公鑰長度: ${rawPublicKeyBuffer.length}B, 簽章長度: ${selftestSig.length}B)`);
        }
    } catch (err) {
        console.error('[錯誤] 金鑰對自我檢驗失敗:', err.message);
        process.exit(1);
    }
}

initKeyPair();

// ==========================================
// 3. 退出信號處理 (Graceful Shutdown)
// ==========================================
// 誠實宣告：JS 層無法保證清零 V8 內部的 KeyObject 緩衝區；此處關閉伺服器、
// 釋放所有金鑰引用並結束進程，實際記憶體回收交由 V8 GC 與 OS。
let isShuttingDown = false;
function shutdownAndReleaseKeys(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log(`\n[信號] 收到 ${signal}，關閉伺服器並釋放金鑰引用...`);
    privateKey = null;
    rawPublicKeyBuffer = null;
    server.close(() => {
        process.exit(0);
    });
    // 若有 Keep-Alive 長連線未即時中斷，1.5 秒後超時強制退出
    setTimeout(() => process.exit(0), 1500).unref();
}

process.on('SIGINT', () => shutdownAndReleaseKeys('SIGINT'));
process.on('SIGTERM', () => shutdownAndReleaseKeys('SIGTERM'));

// ==========================================
// 4. HTTP API 伺服器
// ==========================================
const server = http.createServer((req, res) => {
    // 跨域與安全標頭
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    // 不信任 client 的 Host header：以服務自身位址為 base 解析；無效的 Host /
    // absolute-form request-target 會讓 new URL() 拋例外，必須轉 400 而非 crash 整個服務
    let parsedUrl;
    try {
        const baseHost = HOST.includes(':') && !HOST.startsWith('[') ? `[${HOST}]` : HOST;
        parsedUrl = new URL(req.url, `http://${baseHost}:${PORT}`);
    } catch (_) {
        res.writeHead(400);
        res.end(JSON.stringify({ code: 400, error: '無效的請求 URL' }));
        return;
    }

    // --- 根路徑：服務資訊概覽 ---
    if (req.method === 'GET' && (parsedUrl.pathname === '/' || parsedUrl.pathname === '/health')) {
        const info = {
            service: 'SignCore 64 Remote Signature Service',
            status: 'ONLINE',
            algorithm: 'Ed25519',
            public_key_hex: PUBLIC_KEY_HEX,
            auth_required: Boolean(API_KEY),
            endpoints: {
                publicKey: 'GET  /api/v1/crypto/public-key',
                sign:      'POST /api/v1/crypto/sign',
                verify:    'POST /api/v1/crypto/verify',
                health:    'GET  /health'
            },
            timestamp: Math.floor(Date.now() / 1000)
        };
        res.writeHead(200);
        res.end(JSON.stringify(info, null, 2));
        return;
    }

    // --- 端點 1: GET /api/v1/crypto/public-key ---
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
        console.log(`[GET 200] 遠端查詢公鑰 (${req.socket.remoteAddress}) -> ${PUBLIC_KEY_HEX.substring(0, 16)}...`);
        return;
    }

    // --- 端點 2: POST /api/v1/crypto/sign (亦相容 /crypto/sign) ---
    if (req.method === 'POST' && (parsedUrl.pathname === '/api/v1/crypto/sign' || parsedUrl.pathname === '/crypto/sign')) {
        // 鑑權檢查 (若已設定 SIGNCORE_API_KEY)
        if (API_KEY) {
            const clientAuth = req.headers['x-api-key'] || req.headers['authorization'];
            if (!verifyApiKey(clientAuth, API_KEY)) {
                res.setHeader('WWW-Authenticate', 'Bearer realm="SignCore"');
                res.writeHead(401);
                res.end(JSON.stringify({ code: 401, error: 'Unauthorized: 無效或未提供 API Key (請附帶 X-Api-Key 標頭)' }));
                console.warn(`[POST 401] 拒絕未授權簽署請求 (${req.socket.remoteAddress})`);
                return;
            }
        }

        const chunks = [];
        let totalBytes = 0;
        let tooLarge = false;

        req.on('error', (err) => {
            console.warn(`[POST 串流中斷] 簽署請求 (${req.socket.remoteAddress}):`, err.message);
            if (!res.headersSent) {
                res.writeHead(400);
                res.end(JSON.stringify({ code: 400, error: '請求傳輸中斷: ' + err.message }));
            }
        });

        req.on('data', chunk => {
            if (tooLarge) return;
            chunks.push(chunk);
            totalBytes += chunk.length;
            if (totalBytes > MAX_BODY_BYTES) {
                tooLarge = true;
                res.writeHead(413);
                res.end(JSON.stringify({ code: 413, error: '請求 Payload 超過上限 (1MB)' }));
                req.destroy();
            }
        });

        req.on('end', () => {
            if (tooLarge) return;
            try {
                const reqJson = JSON.parse(Buffer.concat(chunks).toString('utf8'));
                const payload = reqJson.payload;

                // 與 mock/bridge 嚴格一致：僅接受字串 payload，直接簽署其 UTF-8 位元組。
                // 靜默 stringify 物件會產生跨端不可複現的 bytes，破壞 PureEd25519 原始位元組不變量
                if (typeof payload !== 'string') {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'payload 欄位為必填字串' }));
                    return;
                }

                const dataBuffer = Buffer.from(payload, 'utf-8');

                // 使用 Ed25519 私鑰進行簽署
                const sigBuffer = crypto.sign(null, dataBuffer, privateKey);

                if (sigBuffer.length !== 64) {
                    throw new Error(`簽章不變量違反：Ed25519 簽名長度必須為 64 位元組 (實際: ${sigBuffer.length})`);
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
                    signature_r: sigHex.substring(0, 64),
                    signature_s: sigHex.substring(64, 128),
                    signature_base64: sigB64,
                    public_key_hex: PUBLIC_KEY_HEX,
                    payload_sha256: hashHex,
                    timestamp: Math.floor(Date.now() / 1000)
                };

                res.writeHead(200);
                res.end(JSON.stringify(responseData, null, 2));
                console.log(`[POST 200] 簽署成功 (${req.socket.remoteAddress}) - 長度: ${dataBuffer.length}B, 簽名: ${sigHex.substring(0, 16)}...`);
            } catch (err) {
                res.writeHead(400);
                res.end(JSON.stringify({ code: 400, error: '簽署失敗: ' + err.message }));
                console.error(`[POST 400] 簽署失敗:`, err.message);
            }
        });
        return;
    }

    // --- 端點 3: POST /api/v1/crypto/verify (亦相容 /crypto/verify) ---
    if (req.method === 'POST' && (parsedUrl.pathname === '/api/v1/crypto/verify' || parsedUrl.pathname === '/crypto/verify')) {
        const chunks = [];
        let totalBytes = 0;
        let tooLarge = false;

        req.on('error', (err) => {
            console.warn(`[POST 串流中斷] 驗證請求 (${req.socket.remoteAddress}):`, err.message);
            if (!res.headersSent) {
                res.writeHead(400);
                res.end(JSON.stringify({ code: 400, error: '請求傳輸中斷: ' + err.message, valid: false }));
            }
        });

        req.on('data', chunk => {
            if (tooLarge) return;
            chunks.push(chunk);
            totalBytes += chunk.length;
            if (totalBytes > MAX_BODY_BYTES) {
                tooLarge = true;
                res.writeHead(413);
                res.end(JSON.stringify({ code: 413, error: '請求 Payload 超過上限 (1MB)' }));
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

                if (typeof payload !== 'string') {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'payload 欄位為必填字串', valid: false }));
                    return;
                }
                if (typeof sigHex !== 'string' || sigHex.length !== 128 || /[^0-9a-fA-F]/.test(sigHex)) {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'signature_hex 格式錯誤 (應為 128 字元 Hex = 64 Bytes)', valid: false }));
                    return;
                }
                if (typeof pubHex !== 'string' || pubHex.length !== 64 || /[^0-9a-fA-F]/.test(pubHex)) {
                    res.writeHead(400);
                    res.end(JSON.stringify({ code: 400, error: 'public_key_hex 格式錯誤 (應為 64 字元 Hex = 32 Bytes)', valid: false }));
                    return;
                }

                const dataBuffer = Buffer.from(payload, 'utf-8');
                const sigBuffer = Buffer.from(sigHex, 'hex');
                const pubBuffer = Buffer.from(pubHex, 'hex');

                // 構造 Ed25519 SPKI DER 標頭 (12 bytes)
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
                    message: isValid ? '簽章驗證通過 (Valid Signature)' : '簽章無效 (Invalid Signature)'
                }, null, 2));
                console.log(`[POST 200] 驗證請求 (${req.socket.remoteAddress}) -> ${isValid ? 'VALID ✓' : 'INVALID ✗'}`);
            } catch (err) {
                res.writeHead(400);
                res.end(JSON.stringify({ code: 400, error: err.message, valid: false }));
            }
        });
        return;
    }

    // 404
    res.writeHead(404);
    res.end(JSON.stringify({ code: 404, error: '端點不存在 (Not Found)' }));
});

// 監聽伺服器底層錯誤 (如埠號被佔用)
server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`[錯誤] 埠號 ${PORT} 已被其他進程佔用 (EADDRINUSE)，請更換埠號或終止舊進程。`);
    } else {
        console.error('[伺服器錯誤]', err.message);
    }
    process.exit(1);
});

// ==========================================
// 5. 啟動伺服器與資訊顯示
// ==========================================
server.listen(PORT, HOST, () => {
    // 獲取本機所有網卡 IP，方便遠端 Client 連線
    const networkInterfaces = os.networkInterfaces();
    const localIps = [];
    for (const ifaceName of Object.keys(networkInterfaces)) {
        for (const iface of networkInterfaces[ifaceName] || []) {
            if (iface.family === 'IPv4' && !iface.internal) {
                localIps.push(iface.address);
            }
        }
    }

    console.log(`================================================================`);
    console.log(`⚡ SignCore 64 遠端簽章服務已在 [${HOST}:${PORT}] 上線`);
    console.log(`🔑 金鑰來源: ${keySourceDesc}`);
    console.log(`🛡️ 公開金鑰 (32 Bytes / 64 Hex): ${PUBLIC_KEY_HEX}`);
    console.log(`🔒 存取控制: ${API_KEY ? '已啟用 API Key 鑑權 (常數時間校驗)' : '公開模式 (未設定 SIGNCORE_API_KEY)'}`);
    console.log(`[警告] 本服務為明文 HTTP，X-Api-Key 以明文標頭過網：僅限受信任內網使用；跨網路部署請置於 TLS 反向代理之後`);
    if (HOST === '0.0.0.0' && !API_KEY) {
        console.log(`⚠️  [高風險警示] 服務對外開放監聽 (0.0.0.0) 且未設定 SIGNCORE_API_KEY！`);
        console.log(`    任何網路連線者皆可隨意請求簽署任意資料 (Signing Oracle Risk)。`);
    }
    console.log(`----------------------------------------------------------------`);
    console.log(`🌐 遠端 Client 可透過以下網址連線：`);
    if (HOST === '0.0.0.0' && localIps.length > 0) {
        for (const ip of localIps) {
            console.log(`   http://${ip}:${PORT}`);
        }
    } else {
        console.log(`   http://${HOST}:${PORT}`);
    }
    console.log(`----------------------------------------------------------------`);
    console.log(`📡 API 端點一覽：`);
    console.log(`   - 取得公鑰: GET  /api/v1/crypto/public-key`);
    console.log(`   - 產生簽名: POST /api/v1/crypto/sign ${API_KEY ? '(需附帶 X-Api-Key 標頭)' : ''}`);
    console.log(`   - 校驗簽名: POST /api/v1/crypto/verify`);
    console.log(`   - 服務健康: GET  /health`);
    console.log(`================================================================`);
});
