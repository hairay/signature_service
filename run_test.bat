@echo off
chcp 65001 >nul
echo ========================================================
echo  SignCore 64 - C 語言端對端簽署測試 (Windows Batch)
echo ========================================================

echo [1/5] 檢查連接埠 8080 是否可用...
netstat -aon | findstr ":8080" | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [錯誤] 連接埠 8080 已被占用。請釋放該埠或改用 run_test.ps1 -Port ^<其他埠^>。
    pause
    exit /b 1
)

echo [2/5] 編譯 C 語言測試程式...
gcc -o sign_client_test.exe sign_client_test.c -lws2_32
if errorlevel 1 (
    echo [錯誤] 編譯失敗！
    pause
    exit /b 1
)
echo 編譯完成: sign_client_test.exe

echo [3/5] 啟動本機簽章伺服器...
start /B node mock_signature_server.js 8080 >nul 2>&1
timeout /t 1 /nobreak >nul

echo [4/5] 執行測試程式...
sign_client_test.exe 127.0.0.1 8080
set CLIENT_EXIT=%errorlevel%

echo [5/5] 清理：僅終止偵聽 8080 的測試伺服器 PID（不會影響其他 node 程序）
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8080" ^| findstr "LISTENING"') do taskkill /F /PID %%p >nul 2>&1

echo.
if "%CLIENT_EXIT%"=="0" (
    echo 測試結果：全部通過
) else (
    echo 測試結果：有測試未通過 (結束碼 %CLIENT_EXIT%)
)
pause
exit /b %CLIENT_EXIT%
