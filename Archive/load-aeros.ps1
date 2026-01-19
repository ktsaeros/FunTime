<#
.SYNOPSIS
    Aeros IT "FunTime" Loader (v3.1)
    Usage: irm https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/load-aeros.ps1 | iex
#>

# --- CONFIGURATION ---
$Token = $null
# UPDATED PATH: Pointing to the new ToolKit subfolder
$TargetFile = "ToolKit/AerosMaster.ps1" 
$BaseUrl = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/$TargetFile"

# --- THE BULLETPROOF DOWNLOADER ---
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host "   [Aeros IT] Fetching Master Toolkit..." -ForegroundColor Cyan

try {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.Encoding = [System.Text.Encoding]::UTF8
    
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $WebClient.Headers.Add("Authorization", "Bearer $Token")
    }
    
    $ToolboxCode = $WebClient.DownloadString($BaseUrl)
    
    # Run the Master Menu
    Invoke-Expression $ToolboxCode
}
catch {
    Write-Host "   [ERROR] Loader Failed." -ForegroundColor Red
    Write-Host "   Details: $($_.Exception.Message)" -ForegroundColor Gray
}