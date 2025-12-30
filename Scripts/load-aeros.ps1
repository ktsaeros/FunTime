<#
.SYNOPSIS
    Aeros IT "FunTime" Loader
    Usage: irm https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/load-aeros.ps1 | iex
#>

# --- CONFIGURATION ---
$Token = $null  # Paste token here if repo becomes Private
$TargetFile = "AerosTools.ps1" 
$BaseUrl = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/$TargetFile"

# --- THE BULLETPROOF DOWNLOADER ---
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host "   [Aeros IT] Fetching $TargetFile..." -ForegroundColor Cyan

try {
    $WebClient = New-Object System.Net.WebClient
    
    # 1. FORCE UTF-8 ENCODING (Fixes the "Missing Terminator" crash on menus)
    $WebClient.Encoding = [System.Text.Encoding]::UTF8
    
    # 2. Add Auth Header (if token exists)
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $WebClient.Headers.Add("Authorization", "Bearer $Token")
    }
    
    # 3. Download the Toolbox Code
    $ToolboxCode = $WebClient.DownloadString($BaseUrl)
    
    # 4. Load the functions into RAM
    Invoke-Expression $ToolboxCode
    
    # 5. FIND AND LIST AVAILABLE TOOLS
    Clear-Host
    Write-Host "╔════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║       AEROS IT COMMAND CENTER      ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host " The following tools are now ready:`n" -ForegroundColor Gray
    
    # Scan the downloaded string for function names
    $matches = [regex]::Matches($ToolboxCode, "function\s+([\w-]+)")
    if ($matches.Count -gt 0) {
        foreach ($m in $matches) {
            $cmd = $m.Groups[1].Value
            # Skip internal helper functions (optional filter)
            if ($cmd -notmatch "^Decode-") {
                Write-Host "  > $cmd" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "   (No functions found. Check AerosTools.ps1 content)" -ForegroundColor Red
    }
    
    Write-Host "`n Type a command above and press Enter." -ForegroundColor Yellow
}
catch {
    Write-Host "   [ERROR] Loader Failed." -ForegroundColor Red
    Write-Host "   Details: $($_.Exception.Message)" -ForegroundColor Gray
}