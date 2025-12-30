<#
.SYNOPSIS
    Aeros IT "FunTime" Loader
    Usage: irm https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/Loader.ps1 | iex
#>

# --- CONFIGURATION ---
# If your repo is PUBLIC, leave $Token as $null.
# If your repo is PRIVATE, paste your "Fine-grained" token inside the quotes.
$Token = $null  # e.g. "github_pat_11A..."

# The file you want to load. (Combine your tools into one 'AerosTools.ps1' later!)
$TargetFile = "AerosTools.ps1" 
$BaseUrl = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/Scripts/$TargetFile"

# --- THE BULLETPROOF DOWNLOADER ---
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host "   [Aeros IT] Fetching $TargetFile..." -ForegroundColor Cyan

try {
    $WebClient = New-Object System.Net.WebClient
    
    # Only add Auth header if a token exists
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $WebClient.Headers.Add("Authorization", "Bearer $Token")
    }
    
    # 1. Download the code into RAM (No file on disk)
    $ScriptContent = $WebClient.DownloadString($BaseUrl)
    
    # 2. Execute it immediately
    Invoke-Expression $ScriptContent
    
    # 3. (Optional) If you switch to a "Toolbox" model, you can print a menu here.
    # Write-Host "   [OK] Tools Loaded. Run 'Get-AerosHealth' to start." -ForegroundColor Green
}
catch {
    Write-Host "   [ERROR] Failed to download." -ForegroundColor Red
    Write-Host "   Server said: $($_.Exception.Message)" -ForegroundColor Yellow
    if ($_.Exception.Message -match "404") {
        Write-Host "   -> Check if '$TargetFile' exists in the 'Scripts' folder." -ForegroundColor Gray
    }
    if ($_.Exception.Message -match "401|403") {
        Write-Host "   -> Check your Token permissions." -ForegroundColor Gray
    }
}

try {
    # 1. Download the Toolbox
    $ToolboxCode = $WebClient.DownloadString($BaseUrl)
    
    # 2. Load the functions into RAM
    Invoke-Expression $ToolboxCode
    
    # 3. THE USER EXPERIENCE UPGRADE:
    # This automatically finds all functions you just loaded and lists them
    Clear-Host
    Write-Host "╔════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║       AEROS IT COMMAND CENTER      ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host " The following tools are now ready:`n" -ForegroundColor Gray
    
    # Simple regex to find function names in the downloaded code
    $matches = [regex]::Matches($ToolboxCode, "function\s+([\w-]+)")
    foreach ($m in $matches) {
        $cmd = $m.Groups[1].Value
        Write-Host "  > $cmd" -ForegroundColor Green
    }
    
    Write-Host "`n Type a command above and press Enter." -ForegroundColor Yellow
}
catch {
    Write-Host "Error loading tools: $($_.Exception.Message)" -ForegroundColor Red
}