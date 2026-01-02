<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (Hybrid Launcher v2.2 - Debug Edition)
    - Added: URL Debugging (Prints the URL it's trying to fetch)
    - Added: Cache Busting (Forces fresh download)
#>

# ==============================================================================
#  CORE LAUNCHER ENGINE
# ==============================================================================

function Invoke-AerosScript {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName
    )

    # --- CONFIGURATION: REPO ROOT ---
    # Ensure this matches your GitHub folder structure EXACTLY.
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    
    # Add a random number to force a fresh download (Bypass Cache)
    $CacheBust = Get-Random
    $TargetUrl = "$RepoRoot/$ScriptName?v=$CacheBust"

    Write-Host "   [Launcher] Fetching: $ScriptName" -ForegroundColor Cyan
    # DEBUG LINE: Shows you exactly where it is looking
    Write-Host "   [Debug] URL: $TargetUrl" -ForegroundColor DarkGray

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $WebClient = New-Object System.Net.WebClient
        $Code = $WebClient.DownloadString($TargetUrl)

        & { Invoke-Expression $Code }
    }
    catch {
        Write-Error "Failed to launch $ScriptName."
        Write-Error "Error: $($_.Exception.Message)"
        Write-Warning "Check the [Debug] URL above. Does that file exist in your browser?"
    }
}

# ==============================================================================
#  TOOL WRAPPERS
# ==============================================================================

# --- Diagnostics ---
function Get-SystemHealth { Invoke-AerosScript "forensic4.ps1" }
function Get-RAMReport    { Invoke-AerosScript "RAM.ps1" }
function Get-OfficeAudit  { Invoke-AerosScript "oochk.ps1" }
function Get-Users        { Invoke-AerosScript "users.ps1" }
function Get-Battery      { Invoke-AerosScript "battery.ps1" }
function Get-RMMLog       { Invoke-AerosScript "rmmlog.ps1" }

# --- Maintenance ---
function New-Scanner      { Invoke-AerosScript "scanner.ps1" }
function Fix-AccountEdge  { Invoke-AerosScript "Fix-AccountEdge.ps1" }

# --- Security ---
function Enable-BitLocker { Invoke-AerosScript "btlon.ps1" }

# ==============================================================================
#  MAIN MENU
# ==============================================================================

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           AEROS MASTER TOOLKIT (Hybrid)               ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS]" -ForegroundColor Yellow
        Write-Host "  1.  System Health (Forensic4)      4.  User Profile Audit" -ForegroundColor White
        Write-Host "  2.  RAM Analysis                   5.  Battery & UPS Check" -ForegroundColor White
        Write-Host "  3.  Outlook/Office Audit           6.  Tail RMM Logs (Live)" -ForegroundColor White
        
        Write-Host "`n [MAINTENANCE & FIXES]" -ForegroundColor Yellow
        Write-Host "  10. Create Scanner User (SMB)      11. Fix AccountEdge Lock" -ForegroundColor White
        Write-Host "  12. Dell Update (DCU)" -ForegroundColor White
        
        Write-Host "`n [SECURITY]" -ForegroundColor Yellow
        Write-Host "  20. Enforce BitLocker (Escrow Key)" -ForegroundColor White
        
        Write-Host "`n Q. Quit" -ForegroundColor DarkCyan
        
        $sel = Read-Host "`n Command"
        
        switch ($sel) {
            '1'  { Get-SystemHealth; pause }
            '2'  { Get-RAMReport; pause }
            '3'  { Get-OfficeAudit; pause }
            '4'  { Get-Users; pause }
            '5'  { Get-Battery; pause }
            '6'  { Get-RMMLog; pause }
            '10' { New-Scanner; pause }
            '11' { Fix-AccountEdge; pause }
            '12' { Invoke-AerosScript "Dell-Update.ps1"; pause }
            '20' { Enable-BitLocker; pause }
            'Q'  { return }
            'q'  { return }
        }
    }
}

if ($Host.Name -notmatch "ISE|Visual Studio Code") { Start-Aeros }