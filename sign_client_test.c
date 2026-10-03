/**
 * SignCore 64 - C 語言端對端簽署與驗證客戶端測試程式
 * 
 * 功能：
 *   1. 向微服務 GET /api/v1/crypto/public-key 取得 32-Byte 固定公鑰
 *   2. 向微服務 POST /api/v1/crypto/sign 傳送資料取得 64-Byte Ed25519 簽章
 *   3. 拆解簽章為 32B 點 R 與 32B 純量 S，校驗 64-byte 不變量
 *   4. 發送合法資料校驗請求，確認「簽章驗證通過」
 *   5. 發送竄改資料請求，確認「篡改攔截成功」
 * 
 * 編譯方式：
 *   - Windows (GCC / MinGW):  gcc -o sign_client_test.exe sign_client_test.c -lws2_32
 *   - Linux / macOS (GCC):    gcc -o sign_client_test sign_client_test.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define IS_VALIDSOCKET(s) ((s) != INVALID_SOCKET)
    #define CLOSESOCKET(s) closesocket(s)
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    typedef int socket_t;
    #define IS_VALIDSOCKET(s) ((s) >= 0)
    #define CLOSESOCKET(s) close(s)
#endif

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8080
#define BUFFER_SIZE  8192

// 初始化網路環境 (Windows Winsock 需啟動)
int init_networking(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[錯誤] WSAStartup 初始化失敗\n");
        return 0;
    }
#endif
    return 1;
}

void cleanup_networking(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// 發送 HTTP 請求並接收伺服器回應封包
int http_request(const char *host, int port, const char *method, const char *path, const char *body, char *response_out, size_t max_resp_len) {
    socket_t sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (!IS_VALIDSOCKET(sock)) {
        fprintf(stderr, "[錯誤] 無法建立 Socket\n");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    {
        // Prefer dotted-quad; fall back to hostname resolution with an explicit error
        unsigned long addr = inet_addr(host);
        if (addr != INADDR_NONE) {
            server_addr.sin_addr.s_addr = addr;
        } else {
            struct hostent *he = gethostbyname(host);
            if (!he || he->h_addrtype != AF_INET || !he->h_addr_list[0]) {
                fprintf(stderr, "[錯誤] 無法解析主機位址: %s\n", host);
                CLOSESOCKET(sock);
                return 0;
            }
            memcpy(&server_addr.sin_addr, he->h_addr_list[0], sizeof(struct in_addr));
        }
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[錯誤] 無法連線至伺服器 %s:%d\n", host, port);
        CLOSESOCKET(sock);
        return 0;
    }

    // 構造標準 HTTP/1.1 請求報文
    char request_buf[BUFFER_SIZE];
    int body_len = body ? (int)strlen(body) : 0;

    if (body_len > 0) {
        snprintf(request_buf, sizeof(request_buf),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: SignCore-C-Client/1.0\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            method, path, host, port, body_len, body);
    } else {
        snprintf(request_buf, sizeof(request_buf),
            "%s %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "User-Agent: SignCore-C-Client/1.0\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, path, host, port);
    }

    send(sock, request_buf, (int)strlen(request_buf), 0);

    // 接收回應
    size_t total_received = 0;
    int bytes_read;
    while ((bytes_read = recv(sock, response_out + total_received, (int)(max_resp_len - total_received - 1), 0)) > 0) {
        total_received += bytes_read;
        if (total_received >= max_resp_len - 1) break;
    }
    response_out[total_received] = '\0';

    CLOSESOCKET(sock);
    return 1;
}

// 簡易 JSON 字串值擷取函式 (支援任意空白符號)
int extract_json_str(const char *json, const char *key, char *out_val, size_t max_len) {
    char target[128];
    snprintf(target, sizeof(target), "\"%s\"", key);
    char *pos = strstr(json, target);
    if (!pos) return 0;
    pos += strlen(target);
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != ':') return 0;
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != '\"') return 0;
    pos++;
    char *end = strchr(pos, '\"');
    if (!end) return 0;
    size_t len = end - pos;
    if (len >= max_len) len = max_len - 1;
    strncpy(out_val, pos, len);
    out_val[len] = '\0';
    return 1;
}

// 簡易 JSON 布林值擷取函式
int extract_json_bool(const char *json, const char *key, int *out_bool) {
    char target[128];
    snprintf(target, sizeof(target), "\"%s\"", key);
    char *pos = strstr(json, target);
    if (!pos) return 0;
    pos += strlen(target);
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != ':') return 0;
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (strncmp(pos, "true", 4) == 0) {
        *out_bool = 1;
        return 1;
    } else if (strncmp(pos, "false", 5) == 0) {
        *out_bool = 0;
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;

    if (argc >= 2) host = argv[1];
    if (argc >= 3) port = atoi(argv[2]);

    printf("========================================================\n");
    printf(" SignCore 64 - C 語言 Ed25519 簽章與公鑰端對端測試\n");
    printf(" 目標位址: http://%s:%d\n", host, port);
    printf("========================================================\n\n");

    if (!init_networking()) return 1;

    char resp_buf[BUFFER_SIZE];
    int tests_passed = 0;

    // -----------------------------------------------------------
    // 測試 1: 向微服務 GET 獲取 32-Byte 系統公鑰
    // -----------------------------------------------------------
    printf("[測試 1] 查詢伺服器內部固定 Ed25519 公鑰 (GET /api/v1/crypto/public-key)...\n");
    if (!http_request(host, port, "GET", "/api/v1/crypto/public-key", NULL, resp_buf, sizeof(resp_buf))) {
        fprintf(stderr, "測試 1 失敗：無法連線至服務端，請先確認微服務已啟動。\n");
        cleanup_networking();
        return 1;
    }

    char server_pubkey[128] = {0};
    if (extract_json_str(resp_buf, "public_key_hex", server_pubkey, sizeof(server_pubkey))) {
        size_t pub_len = strlen(server_pubkey);
        printf("  -> 取得公鑰 (Hex): %s\n", server_pubkey);
        printf("  -> 公鑰長度: %zu hex chars (%zu Bytes)\n", pub_len, pub_len / 2);
        if (pub_len == 64) {
            printf("  ✓ [PASS] 成功取得系統 Ed25519 公鑰 (符合 32 Bytes 規範)\n\n");
            tests_passed++;
        } else {
            printf("  ✗ [FAIL] 公鑰長度不符合 32 Bytes (預期 64 Hex 字元)\n\n");
        }
    } else {
        printf("  ✗ [FAIL] 無法解析公鑰欄位，回應報文：\n%s\n\n", resp_buf);
    }

    // -----------------------------------------------------------
    // 測試 2: 向微服務 POST 傳送資料並取得 64-Byte 簽章
    // -----------------------------------------------------------
    const char *payload_text = "{\"orderId\":\"ORD-2026-9881\",\"amount\":12500,\"currency\":\"USD\"}";
    printf("[測試 2] 傳送業務資料並請求簽章 (POST /api/v1/crypto/sign)...\n");
    printf("  -> 發送 Payload: %s\n", payload_text);

    char sign_req_body[1024];
    snprintf(sign_req_body, sizeof(sign_req_body),
        "{"
        "\"payload\":\"{\\\"orderId\\\":\\\"ORD-2026-9881\\\",\\\"amount\\\":12500,\\\"currency\\\":\\\"USD\\\"}\","
        "\"encoding\":\"utf-8\","
        "\"nonce\":\"c4ca4238a0b923820dcc509a6f75849b\","
        "\"timestamp\":1790994000"
        "}");

    if (!http_request(host, port, "POST", "/api/v1/crypto/sign", sign_req_body, resp_buf, sizeof(resp_buf))) {
        fprintf(stderr, "測試 2 失敗：簽章請求未成功連線\n");
        cleanup_networking();
        return 1;
    }

    char signature_hex[256] = {0};
    char returned_pubkey[128] = {0};
    char signature_b64[128] = {0};

    if (extract_json_str(resp_buf, "signature_hex", signature_hex, sizeof(signature_hex)) &&
        extract_json_str(resp_buf, "public_key_hex", returned_pubkey, sizeof(returned_pubkey))) {
        
        extract_json_str(resp_buf, "signature_base64", signature_b64, sizeof(signature_b64));
        size_t sig_len = strlen(signature_hex);

        printf("  -> 取得數位簽名 (Hex): %s\n", signature_hex);
        printf("  -> 取得數位簽名 (B64): %s\n", signature_b64);
        printf("  -> 簽名長度: %zu hex chars (%zu Bytes)\n", sig_len, sig_len / 2);

        // 校驗簽章長度並拆分點 R (32B) 與純量 S (32B)
        if (sig_len == 128) {
            char r_part[65] = {0};
            char s_part[65] = {0};
            strncpy(r_part, signature_hex, 64);
            strncpy(s_part, signature_hex + 64, 64);
            printf("  -> 點 R (前 32 Bytes): %s\n", r_part);
            printf("  -> 純量 S (後 32 Bytes): %s\n", s_part);
            printf("  ✓ [PASS] 成功取得 Ed25519 簽章 (符合精確 64 Bytes 核心不變量)\n\n");
            tests_passed++;
        } else {
            printf("  ✗ [FAIL] 簽章長度異常 (非 64 Bytes / 128 Hex，實際長度: %zu hex 字元)\n\n", sig_len);
        }
    } else {
        printf("  ✗ [FAIL] 解析簽章回應失敗，回應報文：\n%s\n\n", resp_buf);
    }

    // -----------------------------------------------------------
    // 測試 3: 正向驗證 (使用公鑰、原始資料與簽章校驗真實性)
    // -----------------------------------------------------------
    printf("[測試 3] 發送正向驗證請求 (POST /api/v1/crypto/verify)...\n");
    char verify_body[2048];
    snprintf(verify_body, sizeof(verify_body),
        "{"
        "\"payload\":\"{\\\"orderId\\\":\\\"ORD-2026-9881\\\",\\\"amount\\\":12500,\\\"currency\\\":\\\"USD\\\"}\","
        "\"signature_hex\":\"%s\","
        "\"public_key_hex\":\"%s\""
        "}",
        signature_hex, returned_pubkey);

    if (http_request(host, port, "POST", "/api/v1/crypto/verify", verify_body, resp_buf, sizeof(resp_buf))) {
        int is_valid = 0;
        if (extract_json_bool(resp_buf, "valid", &is_valid) && is_valid == 1) {
            printf("  ✓ [PASS] 簽章正向驗證通過 (Valid Signature：資料完整且由原伺服器簽署)\n\n");
            tests_passed++;
        } else {
            printf("  ✗ [FAIL] 簽章正向驗證未通過，回應報文：\n%s\n\n", resp_buf);
        }
    } else {
        printf("  ✗ [FAIL] 測試 3 請求連線失敗 (POST /api/v1/crypto/verify)\n\n");
    }

    // -----------------------------------------------------------
    // 測試 4: 篡改攔截測試 (竄改 1 個字元，確認驗證失敗)
    // -----------------------------------------------------------
    printf("[測試 4] 注入竄改資料以測試安全攔截 (POST /api/v1/crypto/verify)...\n");
    char tampered_body[2048];
    snprintf(tampered_body, sizeof(tampered_body),
        "{"
        "\"payload\":\"{\\\"orderId\\\":\\\"ORD-2026-9881\\\",\\\"amount\\\":99999,\\\"currency\\\":\\\"USD\\\"}\"," // amount 被竄改為 99999
        "\"signature_hex\":\"%s\","
        "\"public_key_hex\":\"%s\""
        "}",
        signature_hex, returned_pubkey);

    if (http_request(host, port, "POST", "/api/v1/crypto/verify", tampered_body, resp_buf, sizeof(resp_buf))) {
        int is_valid = 1;
        if (extract_json_bool(resp_buf, "valid", &is_valid) && is_valid == 0) {
            printf("  ✓ [PASS] 竄改資料成功被攔截 (Tamper Detection Passed：金額被竄改後簽章立即失效)\n\n");
            tests_passed++;
        } else {
            printf("  ✗ [FAIL] 竄改攔截失效\n\n");
        }
    } else {
        printf("  ✗ [FAIL] 測試 4 請求連線失敗 (POST /api/v1/crypto/verify)\n\n");
    }

    cleanup_networking();

    printf("========================================================\n");
    if (tests_passed == 4) {
        printf(" 測試成果：全部 4 項測試通過！(100%% SUCCESS)\n");
    } else {
        printf(" 測試成果：%d / 4 項測試通過\n", tests_passed);
    }
    printf("========================================================\n");

    return (tests_passed == 4) ? 0 : 1;
}
