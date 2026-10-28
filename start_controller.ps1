# PowerShell launcher for Laboratory Cloud Controller
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONPATH = $scriptDir
$python = "C:\Users\om\AppData\Local\Programs\Python\Python312\python.exe"
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "Starting Laboratory Cloud Controller..." -ForegroundColor Green
Write-Host "Dashboard: http://localhost:8080" -ForegroundColor Yellow
Write-Host "Swagger:   http://localhost:8080/docs" -ForegroundColor Yellow
Write-Host "===============================================================" -ForegroundColor Cyan
& $python -m cloud_controller
