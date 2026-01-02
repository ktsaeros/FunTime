<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (Hybrid v2.6 - Clean URL)
    - REMOVED: Cache buster (?v=...) as it was causing 404s.
    - ADDED: Error details to catch block.
#>

function Invoke-AerosScript {
    param([string]$ScriptName)
    
    # EXACT URL Structure that passed your manual test
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$RepoRoot/$ScriptName"

    Write-Host "   [Launcher] Fetching: $ScriptName" -ForegroundColor Cyan
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $WebClient = New-Object System.Net.WebClient
        $Code = $WebClient.DownloadString($TargetUrl)
        
        # Execute in child scope
        & { Invoke-Expression $Code }
    }
    catch {
        # This will now show you the REAL error (404, 403, etc) instead of just "Failed"
        Write-Error "Failed to launch $ScriptName."
        Write-Host "   [Error] $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.InnerException) {
            Write-Host "   [Inner] $($_.Exception.InnerException.Message)" -ForegroundColor Red
        }
    }
}

# --- Tool Mapping ---
function Get-SystemHealth { Invoke-AerosScript "forensic4.ps1" }
function Get-RAMReport    { Invoke-AerosScript "RAM.ps1" }
function Get-OfficeAudit  { Invoke-AerosScript "oochk.ps1" }
function Get-Users        { Invoke-AerosScript "users.ps1" }
function Get-Battery      { Invoke-AerosScript "battery.ps1" }
function Get-RMMLog       { Invoke-AerosScript "rmmlog.ps1" }
function Get-Drives       { Invoke-AerosScript "map.ps1" }
function Get-Storage      { Invoke-AerosScript "Get-StorageUsage.ps1" }

function New-Scanner      { Invoke-AerosScript "scanner.ps1" }
function Fix-AccountEdge  { Invoke-AerosScript "Fix-AccountEdge.ps1" }
function Install-Apps     { Invoke-AerosScript "Install-AerosApps.ps1" }
function Install-SC       { Invoke-AerosScript "getSC.ps1" }
function Dell-Update      { Invoke-AerosScript "Dell-Update.ps1" }

function Enable-BitLocker { Invoke-AerosScript "btlon.ps1" }
function Gen-Password     { Invoke-AerosScript "Generate-Passwords.ps1" }
function Set-Policies     { Invoke-AerosScript "Set-SecurityPolicies.ps1" }

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           AEROS MASTER TOOLKIT (Hybrid v2.6)          ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS]" -ForegroundColor Yellow
        Write-Host "  1.  System Health (Forensic4)      5.  Battery & UPS Check" -ForegroundColor White
        Write-Host "  2.  RAM Analysis                   6.  Tail RMM Logs (Live)" -ForegroundColor White
        Write-Host "  3.  Outlook/Office Audit           7.  Get Mapped Drives (All Users)" -ForegroundColor White
        Write-Host "  4.  User Profile Audit             8.  Get Folder/File Sizes" -ForegroundColor White
        
        Write-Host "`n [MAINTENANCE & INSTALL]" -ForegroundColor Yellow
        Write-Host "  10. Create Scanner User (SMB)      13. Install Apps (Basic/Power)" -ForegroundColor White
        Write-Host "  11. Fix AccountEdge Lock           14. Install ScreenConnect" -ForegroundColor White
        Write-Host "  12. Dell Update (DCU)"
        
        Write-Host "`n [SECURITY]" -ForegroundColor Yellow
        Write-Host "  20. Enforce BitLocker (Escrow)     22. Password Generator (10x)" -ForegroundColor White
        Write-Host "  21. Password Expiry Policies"
        
        Write-Host "`n Q. Quit" -ForegroundColor DarkCyan
        
        $sel = Read-Host "`n Command"
        
        switch ($sel) {
            '1'  { Get-SystemHealth; pause }
            '2'  { Get-RAMReport; pause }
            '3'  { Get-OfficeAudit; pause }
            '4'  { Get-Users; pause }
            '5'  { Get-Battery; pause }
            '6'  { Get-RMMLog; pause }
            '7'  { Get-Drives; pause }
            '8'  { Get-Storage; pause }

            '10' { New-Scanner; pause }
            '11' { Fix-AccountEdge; pause }
            '12' { Dell-Update; pause }
            '13' { Install-Apps; pause }
            '14' { Install-SC; pause }

            '20' { Enable-BitLocker; pause }
            '21' { Set-Policies; pause }
            '22' { Gen-Password; pause }
            
            'Q'  { return }
            'q'  { return }
        }
    }
}

if ($Host.Name -notmatch "ISE|Visual Studio Code") { Start-Aeros }