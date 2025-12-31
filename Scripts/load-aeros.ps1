<#
.SYNOPSIS
    Aeros IT "FunTime" Loader (v3.0)
    Usage: irm https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/load-aeros.ps1 | iex
#>

# --- CONFIGURATION ---
$Token = $null
$TargetFile = "AerosTools.ps1" 
$BaseUrl = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/$TargetFile"

# --- THE BULLETPROOF DOWNLOADER ---
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host "   [Aeros IT] Fetching $TargetFile..." -ForegroundColor Cyan

try {
    $WebClient = New-Object System.Net.WebClient
    
    # 1. FORCE UTF-8 ENCODING
    $WebClient.Encoding = [System.Text.Encoding]::UTF8
    
    # 2. Add Auth Header (if token exists)
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $WebClient.Headers.Add("Authorization", "Bearer $Token")
    }
    
    # 3. Download the Toolbox Code
    $ToolboxCode = $WebClient.DownloadString($BaseUrl)
    
    # 4. Load the functions into RAM
    Invoke-Expression $ToolboxCode
    
    # 5. AUTO-START THE MENU
    Start-Aeros
}
catch {
    Write-Host "   [ERROR] Loader Failed." -ForegroundColor Red
    Write-Host "   Details: $($_.Exception.Message)" -ForegroundColor Gray
}