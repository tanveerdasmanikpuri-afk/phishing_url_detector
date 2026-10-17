# PowerShell Launcher for Phishing URL Detector
Set-Location -Path $PSScriptRoot

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       Phishing URL Detector - PowerShell Launcher      " -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan

if (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "Starting local application with Python server..." -ForegroundColor Yellow
    python launch.py
} else {
    Write-Host "Opening index.html directly in your default browser..." -ForegroundColor Yellow
    Start-Process (Join-Path $PSScriptRoot "index.html")
}
