param([int]$Port = 8080)
# SignCore 64 - Test Runner (gcc + node in PATH required; exit code reflects test result)
$ErrorActionPreference = 'Stop'
Write-Host "========================================================"
Write-Host " SignCore 64 - Automated End-to-End Test (port $Port)"
Write-Host "========================================================"

Write-Host "Step 0: Checking port $Port availability..."
$occupied = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($occupied) {
    Write-Host "Port $Port is already in use (PID $($occupied[0].OwningProcess)). Aborting to avoid killing an unrelated process." -ForegroundColor Red
    exit 1
}

Write-Host "Step 1: Compiling C client (sign_client_test.c)..."
gcc -o sign_client_test.exe sign_client_test.c -lws2_32
if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation failed"
    exit 1
}
Write-Host "Compilation successful: sign_client_test.exe"

Write-Host "Step 2: Starting mock server (node mock_signature_server.js $Port)..."
$serverProcess = Start-Process node -ArgumentList @("mock_signature_server.js", "$Port") -PassThru -WindowStyle Hidden

# Health-check loop: wait up to ~5s instead of a blind 1s sleep
$ready = $false
for ($i = 0; $i -lt 20; $i++) {
    try {
        $probe = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$Port/api/v1/crypto/public-key" -TimeoutSec 1
        if ($probe.StatusCode -eq 200) { $ready = $true; break }
    } catch {
        Start-Sleep -Milliseconds 250
    }
}
if (-not $ready) {
    Write-Host "Mock server failed to start on port $Port" -ForegroundColor Red
    if ($serverProcess) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
    exit 1
}
Write-Host "Mock server ready at http://127.0.0.1:$Port"

Write-Host "Step 3: Running C test client..."
$clientExit = 1
try {
    .\sign_client_test.exe 127.0.0.1 $Port
    if ($LASTEXITCODE -ne $null) {
        $clientExit = $LASTEXITCODE
    }
} catch {
    Write-Host "Execution of sign_client_test.exe failed: $_" -ForegroundColor Red
    $clientExit = 1
} finally {
    if ($serverProcess) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        Write-Host "Mock server stopped."
    }
}

exit $clientExit
