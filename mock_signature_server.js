/**
 * SignCore 64 - Ed25519 數位簽章本機測試微服務
 * 規格完全依據 ed25519_cryptographic_signature_service_platform.html API 設計
 * 零第三方依賴，使用 Node.js 原生 http 與 crypto 模組
 */

const http = require('http');
const crypto = require('crypto');

const PORT = Number(process.argv[2]) || 8080;
const HOST = '127.0.0.1';
const MAX_BODY_BYTES = 1024 * 1024; // 1MB 請求體上限

// 1. 初始化服務端內部 Ed25519 固定金鑰對 (模擬 HSM / KMS 保管)
console.log('正在初始化 Ed25519 內部固定金鑰對...');
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

// 取得 32-Byte Raw Public Key
const rawPub = publicKey.export({ type: 'spki', format: 'der' }).subarray(12);
const PUBLIC_KEY_HEX = rawPub.toString('hex');
console.log(`[HSM ONLINE] 服務端公鑰 (32 Bytes): ${PUBLIC_KEY_HEX}`);

// 2. 建立 HTTP API 伺服器
const server = http.createServer((req, res) => {
    // 設置 CORS 與 JSON Header
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

    // 端點 3: POST /api/v1/crypto/verify (供測試程式校驗)
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

                // 欄位格式前置校驗：與 local_signature_bridge.js 對齊，給呼叫端可讀的 400 訊息
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
    console.log(`SignCore 64 模擬簽章伺服器已啟動: http://${HOST}:${PORT}`);
    console.log(`- 取得公鑰: GET  http://${HOST}:${PORT}/api/v1/crypto/public-key`);
    console.log(`- 資料簽名: POST http://${HOST}:${PORT}/api/v1/crypto/sign`);
    console.log(`- 簽章驗證: POST http://${HOST}:${PORT}/api/v1/crypto/verify`);
    console.log(`====================================================`);
});
