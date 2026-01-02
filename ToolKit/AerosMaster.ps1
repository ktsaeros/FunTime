<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (Hybrid v2.9)
    Added: Power Enforcer, UPS Agent, Speedtest
#>

# --- Loaders ---
function Invoke-AerosScript {
    param([string]$ScriptName)
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$RepoRoot/$ScriptName" 

    Write-Host "   [Launcher] Fetching: $ScriptName" -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $WebClient = New-Object System.Net.WebClient
        $Code = $WebClient.DownloadString($TargetUrl)
        & { Invoke-Expression $Code }
    }
    catch {
        Write-Error "Failed to launch $ScriptName."
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-AerosTool {
    param([string]$ScriptName, [string]$Arguments)
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$RepoRoot/$ScriptName"
    $TempPath  = "$env:TEMP\$ScriptName"

    Write-Host "   [Tool] Downloading: $ScriptName..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($TargetUrl, $TempPath)
        
        Write-Host "   [Tool] Executing with args: $Arguments" -ForegroundColor Gray
        $Cmd = "$TempPath $Arguments"
        Invoke-Expression "& $Cmd"
        
        Remove-Item $TempPath -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error "Failed to run tool."
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
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
function Get-ForensicMaster { Invoke-AerosScript "Forensic-Master.ps1" }

function New-Scanner      { Invoke-AerosScript "scanner.ps1" }
function Fix-AccountEdge  { Invoke-AerosScript "Fix-AccountEdge.ps1" }
function Install-Apps     { Invoke-AerosScript "Install-AerosApps.ps1" }
function Install-SC       { Invoke-AerosScript "getSC.ps1" }
function Dell-Update      { Invoke-AerosScript "Dell-Update.ps1" }
function Install-PS7      { Invoke-AerosScript "Install-PS7.ps1" }
function Kick-EDR         { Invoke-AerosScript "edrkick.ps1" }         
function Get-Incidents    { Invoke-AerosScript "get-incidents.ps1" }   

# --- NEW TOOLS ---
function Invoke-PowerEnforce { Invoke-AerosTool "power-enforce.ps1" "-PowerButtonAction 1" }
function Invoke-SpeedTest    { Invoke-AerosTool "speedtest.ps1" "" }
function Invoke-UpsCheck     { Invoke-AerosTool "upslog.ps1" "-Snapshot" }
function Install-UpsLogger   { Invoke-AerosTool "upslog.ps1" "-Install -IntervalSeconds 10" }

function Enable-BitLocker { Invoke-AerosScript "btlon.ps1" }
function Gen-Password     { Invoke-AerosScript "Generate-Passwords.ps1" }
function Set-Policies     { Invoke-AerosScript "Set-SecurityPolicies.ps1" }

function Get-MonitorInfo   { Invoke-AerosTool "Get-MonitorInventory.ps1" }
function Start-ImageRepair { Invoke-AerosTool "Repair-WindowsHealth.ps1" }

function Clean-CDrive     { Invoke-AerosTool "cclean.ps1" "" }

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           AEROS MASTER TOOLKIT (Hybrid v2.9)          ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS]" -ForegroundColor Yellow
        Write-Host "  1.  System Health (Forensic4)      5.  Battery & UPS Check" -ForegroundColor White
        Write-Host "  2.  RAM Analysis                   6.  Tail RMM Logs (Live)" -ForegroundColor White
        Write-Host "  3.  Outlook/Office Audit           7.  Get Mapped Drives (All Users)" -ForegroundColor White
        Write-Host "  4.  User Profile Audit             8.  Get Folder/File Sizes" -ForegroundColor White
        Write-Host "  41. Network SpeedTest (Ookla)      9.  ** MASTER FORENSIC REPORT **" -ForegroundColor Green
        Write-Host "  42. Monitor Inventory (Serials)    19. Auto-Repair Windows (SFC/DISM)" -ForegroundColor White
        
        Write-Host "`n [MAINTENANCE & INSTALL]" -ForegroundColor Yellow
        Write-Host "  10. Create Scanner User (SMB)      14. Install ScreenConnect" -ForegroundColor White
        Write-Host "  11. Fix AccountEdge Lock           15. Install PowerShell 7" -ForegroundColor White
        Write-Host "  12. Dell Update (DCU)              16. Kick RMM/EDR Agent" -ForegroundColor White
        Write-Host "  13. Install Apps (Basic/Power)     17. Power Policy Enforcer (One-Off)" -ForegroundColor White
        Write-Host "  24. Clean up C:\ Drive             18. Install UPS Logger (Service)" -ForegroundColor White

        Write-Host "`n [SECURITY & LOGS]" -ForegroundColor Yellow
        Write-Host "  20. Enforce BitLocker (Escrow)     22. Password Generator (10x)" -ForegroundColor White
        Write-Host "  21. Password Expiry Policies       23. Incident Time Machine" -ForegroundColor White
        
        Write-Host "`n Q. Quit" -ForegroundColor DarkCyan
        
        $sel = Read-Host "`n Command"
        
        switch ($sel) {
            '1'  { Get-SystemHealth; pause }
            '2'  { Get-RAMReport; pause }
            '3'  { Get-OfficeAudit; pause }
            '4'  { Get-Users; pause }
            '5'  { Get-Battery; Invoke-UpsCheck; pause } # Added UPS Check here
            '6'  { Get-RMMLog; pause }
            '7'  { Get-Drives; pause }
            '8'  { Get-Storage; pause }
            '9'  { Get-ForensicMaster; pause }
            '41' { Invoke-SpeedTest; pause }

            '10' { New-Scanner; pause }
            '11' { Fix-AccountEdge; pause }
            '12' { Dell-Update; pause }
            '13' { Install-Apps; pause }
            '14' { Install-SC; pause }
            '15' { Install-PS7; pause }
            '16' { Kick-EDR; pause }
            '17' { Invoke-PowerEnforce; pause }
            '18' { Install-UpsLogger; pause }

            '20' { Enable-BitLocker; pause }
            '21' { Set-Policies; pause }
            '22' { Gen-Password; pause }
            '23' { Get-Incidents; pause }
            '42' { Get-MonitorInfo; pause }
            '19' { Start-ImageRepair; pause }
            '24' { Clean-CDrive; pause }

            'Q'  { return }
            'q'  { return }
        }
    }
}

if ($Host.Name -notmatch "ISE|Visual Studio Code") { Start-Aeros }