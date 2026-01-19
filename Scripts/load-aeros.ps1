<#
.SYNOPSIS
    Aeros IT "FunTime" Loader (v4.0)
    Production: irm https://crisps.fit/a | iex
    Development: irm https://crisps.fit/d | iex
#>

# --- 1. BRANCH DETECTION ---
# We determine the branch by looking at how this script was invoked.
# If the command contains "/d" or "/dev/", we pull from the dev branch.
$Branch = "main"
if ($MyInvocation.Line -match "/d" -or $MyInvocation.MyCommand.Definition -match "/dev/") {
    $Branch = "dev"
}

$TargetFile = "AerosMaster.ps1" 
$RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/$Branch"
$BaseUrl = "$RepoRoot/Scripts/$TargetFile"

# --- 2. THE BULLETPROOF DOWNLOADER ---
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host "   [Aeros IT] Fetching $TargetFile ($($Branch.ToUpper()))..." -ForegroundColor Cyan

try {
    # We use Invoke-RestMethod with a Cache-Control header to bypass ISP/GitHub caching
    $Headers = @{ "Cache-Control" = "no-cache" }
    $ToolboxCode = Invoke-RestMethod -Uri $BaseUrl -Headers $Headers -UseBasicParsing
    
    # 3. Load the functions into RAM
    Invoke-Expression $ToolboxCode
    
    # 4. START THE MENU (Passing the branch context to the toolkit)
    Start-Aeros -Branch $Branch
}
catch {
    Write-Host "   [ERROR] Loader Failed to reach $Branch branch." -ForegroundColor Red
    Write-Host "   Details: $($_.Exception.Message)" -ForegroundColor Gray
}