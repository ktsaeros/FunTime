<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (Hybrid v3.1)
    Updated: Re-organized numbering, TLS 1.2, Cache Busting
#>

# --- Loaders ---
function Invoke-AerosScript {
    param([string]$ScriptName)
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$RepoRoot/$ScriptName" # Temporarily removed ?nocache to rule out edge-case 404s
    
    # Enforce TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Host "   [Launcher] Fetching: $ScriptName" -ForegroundColor Cyan
    
    try {
        # Switch to Native PowerShell (IRM) - Matches your successful bootstrapper
        $Code = Invoke-RestMethod -Uri $TargetUrl -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache"; "User-Agent" = "Mozilla/5.0" }
        & { Invoke-Expression $Code }
    }
    catch {
        Write-Error "Failed to launch $ScriptName."
        Write-Host "   [Debug] URL: $TargetUrl" -ForegroundColor Red
        Write-Host "   [Debug] Err: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-AerosTool {
    param([string]$ScriptName, [string]$Arguments)
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$RepoRoot/$ScriptName"
    $TempPath  = "$env:TEMP\$ScriptName"
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Host "   [Tool] Downloading: $ScriptName..." -ForegroundColor Cyan
    
    try {
        # Switch to Native PowerShell (IWR)
        Invoke-WebRequest -Uri $TargetUrl -OutFile $TempPath -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache"; "User-Agent" = "Mozilla/5.0" }
        
        Write-Host "   [Tool] Executing with args: $Arguments" -ForegroundColor Gray
        $Cmd = "$TempPath $Arguments"
        Invoke-Expression "& $Cmd"
        
        Remove-Item $TempPath -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error "Failed to run tool."
        Write-Host "   [Debug] URL: $TargetUrl" -ForegroundColor Red
        Write-Host "   [Debug] Err: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- Tool Mapping ---

# [1-19] Diagnostics & Reporting
function Get-SystemHealth   { Invoke-AerosScript "forensic4.ps1" }
function Get-RAMReport      { Invoke-AerosScript "RAM.ps1" }
function Get-OfficeAudit    { Invoke-AerosScript "oochk.ps1" }
function Get-MonitorInfo    { Invoke-AerosTool "Get-MonitorInventory.ps1" "" }
function Get-Battery        { Invoke-AerosScript "battery.ps1" }
function Get-RMMLog         { Invoke-AerosScript "rmmlog.ps1" }
function Get-Drives         { Invoke-AerosScript "map.ps1" }
function Get-Storage        { Invoke-AerosScript "Get-StorageUsage.ps1" }
function Get-DiskInv        { Invoke-AerosTool "Get-DiskInventory.ps1" "" }
function Get-OSAge          { Invoke-AerosTool "Get-OSAge.ps1" "" }
function Invoke-SpeedTest   { Invoke-AerosTool "speedtest.ps1" "" }
function Verify-BelMonitor  { Invoke-AerosTool "Verify-BelMonitor.ps1" "" }
function Get-ForensicMaster { Invoke-AerosScript "Forensic-Master.ps1" }
function Audit-UserMap      { 
    $u = Read-Host "Enter Username"
    Invoke-AerosTool "Audit-UserDrives.ps1" "-TargetUser $u" 
}
function Invoke-UpsCheck    { Invoke-AerosTool "upslog.ps1" "-Snapshot" }

# [20-39] Maintenance & Install
function New-Scanner        { Invoke-AerosScript "scanner.ps1" }
function Fix-AccountEdge    { Invoke-AerosScript "Fix-AccountEdge.ps1" }
function Dell-Update        { Invoke-AerosScript "Dell-Update.ps1" }
function Install-Apps       { Invoke-AerosScript "Install-AerosApps.ps1" }
function Install-SC         { Invoke-AerosScript "getSC.ps1" }
function Install-PS7        { Invoke-AerosScript "Install-PS7.ps1" }
function Kick-EDR           { Invoke-AerosScript "edrkick.ps1" }
function Invoke-PowerEnforce { Invoke-AerosTool "power-enforce.ps1" "-PowerButtonAction 1" }
function Install-UpsLogger  { Invoke-AerosTool "upslog.ps1" "-Install -IntervalSeconds 10" }
function Start-ImageRepair  { Invoke-AerosTool "Repair-WindowsHealth.ps1" "" }
function Clean-CDrive       { Invoke-AerosTool "cclean.ps1" "" }
function Remove-DellCmd     { Invoke-AerosTool "Remove-DellCommand.ps1" "" }
function Clean-OfficeMRU    { Invoke-AerosTool "Clean-OfficeMRU.ps1" "" }

# [40-50] Security & Logs
function Enable-BitLocker   { Invoke-AerosScript "btlon.ps1" }
function Set-Policies       { Invoke-AerosScript "Set-SecurityPolicies.ps1" }
function Gen-Password       { Invoke-AerosScript "Generate-Passwords.ps1" }
function Get-Incidents      { Invoke-AerosScript "get-incidents.ps1" }
function Invoke-VirtualDisplay { Invoke-AerosScript "usbmmidd.ps1" }

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           AEROS MASTER TOOLKIT (Hybrid v3.1)          ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS & AUDIT]" -ForegroundColor Yellow
        Write-Host "  1.  System Health (Forensic4)      9.  Network SpeedTest (Ookla)" -ForegroundColor White
        Write-Host "  2.  RAM Analysis                   10. Monitor Inventory (Serials)" -ForegroundColor White
        Write-Host "  3.  Outlook/Office Audit           11. Disk/Storage Inventory" -ForegroundColor White
        Write-Host "  4.  Battery & UPS Check            12. OS Install Date Check" -ForegroundColor White
        Write-Host "  5.  Tail RMM Logs (Live)           13. Audit Offline Mapped Drives" -ForegroundColor White
        Write-Host "  6.  Get Mapped Drives (Active)     14. Verify BelMonitor/GWN Post" -ForegroundColor White
        Write-Host "  7.  Get Folder/File Sizes          15. ** MASTER FORENSIC REPORT **" -ForegroundColor Green
        
        Write-Host "`n [MAINTENANCE & INSTALL]" -ForegroundColor Yellow
        Write-Host "  20. Create Scanner User (SMB)      27. Power Policy Enforcer (One-Off)" -ForegroundColor White
        Write-Host "  21. Fix AccountEdge Lock           28. Install UPS Logger (Service)" -ForegroundColor White
        Write-Host "  22. Dell Update (DCU)              29. Auto-Repair Windows (SFC/DISM)" -ForegroundColor White
        Write-Host "  23. Install Apps (Basic/Power)     30. Clean up C:\ Drive (Smart)" -ForegroundColor White
        Write-Host "  24. Install ScreenConnect          31. Remove Dell Command Update" -ForegroundColor Red
        Write-Host "  25. Install PowerShell 7           32. Clean Office MRU/CloudRecents" -ForegroundColor Gray
        Write-Host "  26. Kick RMM/EDR Agent            33. Virtual Display Manager" -ForegroundColor White

        Write-Host "`n [SECURITY & LOGS]" -ForegroundColor Yellow
        Write-Host "  40. Enforce BitLocker (Escrow)     42. Password Generator (10x)" -ForegroundColor White
        Write-Host "  41. Password Expiry Policies       43. Incident Time Machine" -ForegroundColor White
        
        Write-Host "`n Q. Quit" -ForegroundColor DarkCyan
        
        $sel = Read-Host "`n Command"
        
        switch ($sel) {
            # Diagnostics
            '1'  { Get-SystemHealth; pause }
            '2'  { Get-RAMReport; pause }
            '3'  { Get-OfficeAudit; pause }
            '4'  { Get-Battery; Invoke-UpsCheck; pause }
            '5'  { Get-RMMLog; pause }
            '6'  { Get-Drives; pause }
            '7'  { Get-Storage; pause }
            '9'  { Invoke-SpeedTest; pause }
            '10' { Get-MonitorInfo; pause }
            '11' { Get-DiskInv; pause }
            '12' { Get-OSAge; pause }
            '13' { Audit-UserMap; pause }
            '14' { Verify-BelMonitor; pause }
            '15' { Get-ForensicMaster; pause }

            # Maintenance
            '20' { New-Scanner; pause }
            '21' { Fix-AccountEdge; pause }
            '22' { Dell-Update; pause }
            '23' { Install-Apps; pause }
            '24' { Install-SC; pause }
            '25' { Install-PS7; pause }
            '26' { Kick-EDR; pause }
            '27' { Invoke-PowerEnforce; pause }
            '28' { Install-UpsLogger; pause }
            '29' { Start-ImageRepair; pause }
            '30' { Clean-CDrive; pause }
            '31' { Remove-DellCmd; pause }
            '32' { Clean-OfficeMRU; pause }
            '33' { Invoke-VirtualDisplay; pause }

            # Security
            '40' { Enable-BitLocker; pause }
            '41' { Set-Policies; pause }
            '42' { Gen-Password; pause }
            '43' { Get-Incidents; pause }
            
            'Q'  { return }
            'q'  { return }
        }
    }
}

if ($Host.Name -notmatch "ISE|Visual Studio Code") { Start-Aeros }