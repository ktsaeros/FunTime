<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (Hybrid v3.1.1.b)
    Fixed: String termination errors and ampersand parsing issues.
#>

# --- Loaders ---
function Invoke-AerosScript {
    param([string]$ScriptName)
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$RepoRoot/$ScriptName"
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "   [Launcher] Fetching: $ScriptName" -ForegroundColor Cyan
    
    try {
        $Code = Invoke-RestMethod -Uri $TargetUrl -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache"; "User-Agent" = "Mozilla/5.0" }
        & { Invoke-Expression $Code }
    }
    catch {
        Write-Error "Failed to launch $ScriptName."
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
        Invoke-WebRequest -Uri $TargetUrl -OutFile $TempPath -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache" }
        $Cmd = "$TempPath $Arguments"
        Invoke-Expression "& $Cmd"
        Remove-Item $TempPath -ErrorAction SilentlyContinue
    }
    catch {
        Write-Error "Failed to run tool."
    }
}

# --- Tool Mapping ---
function Get-SystemHealth   { Invoke-AerosTool "forensic4.ps1" }
function Get-RAMReport      { Invoke-AerosScript "RAM.ps1" }
function Get-OfficeAudit    { Invoke-AerosScript "oochk.ps1" }
function Get-MonitorInfo    { Invoke-AerosTool "Get-MonitorInventory.ps1" "" }
function Get-Battery        { Invoke-AerosScript "battery.ps1" }
function Get-RMMLog         { Invoke-AerosScript "rmmlog.ps1" }
function Get-DiskInv        { Invoke-AerosTool "Get-DiskInventory.ps1" "" }
function Get-OSAge          { Invoke-AerosTool "Get-OSAge.ps1" "" }
function Invoke-SpeedTest   { Invoke-AerosTool "speedtest.ps1" "" }
function Verify-BelMonitor  { Invoke-AerosTool "Verify-BelMonitor.ps1" "" }
function Get-ForensicMaster { Invoke-AerosScript "Forensic-Master.ps1" }
function Invoke-UpsCheck    { Invoke-AerosTool "upslog.ps1" "-Snapshot" }

# Unified Storage & User Audit
function Get-StorageAudit   { Invoke-AerosScript "storage-audit.ps1" }

# Maintenance & Displays
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
function Invoke-VirtualDisp  { Invoke-AerosScript "usbmmidd.ps1" }
function Invoke-XfrHelpr    { Invoke-}

# Security
function Enable-BitLocker   { Invoke-AerosScript "btlon.ps1" }
function Set-Policies       { Invoke-AerosScript "Set-SecurityPolicies.ps1" }
function Gen-Password       { Invoke-AerosScript "Generate-Passwords.ps1" }
function Get-Incidents      { Invoke-AerosScript "get-incidents.ps1" }

function Invoke-TransferWizard {
    Clear-Host
    Write-Host " [AEROS TRANSFER WIZARD]" -ForegroundColor Cyan
    Write-Host " 1. Sender Mode (Fix Perms & Move)"
    Write-Host " 2. Receiver Mode (Start Download Job)"
    Write-Host " 3. Check Job Status"
    Write-Host " Q. Cancel"
    
    $sel = Read-Host " Select Option"
    
    # --- SENDER MODE ---
    if ($sel -eq '1') {
        Write-Host "`n --- SENDER CONFIG ---" -ForegroundColor Yellow
        
        # 1. Source Path (Mandatory)
        $src = Read-Host " Source Path [Required] (e.g. C:\Users\Missy\Downloads\Setup.exe)"
        if (-not $src) { Write-Host " [!] Cancelled." -ForegroundColor Red; return }

        # 2. Destination Path (Optional - Default Provided)
        $defDest = "C:\Users\Public\Documents\Intuit\QuickBooks"
        $dest = Read-Host " Destination Path [Default: $defDest]"
        if (-not $dest) { $dest = $defDest }
        
        # Launch Tool
        Invoke-AerosTool "Transfer-Helper.ps1" "-Mode Sender -SourcePath '$src' -DestPath '$dest'"
    }

    # --- RECEIVER MODE ---
    elseif ($sel -eq '2') {
        Write-Host "`n --- RECEIVER CONFIG ---" -ForegroundColor Yellow
        
        # 1. Remote Host (Mandatory)
        $rHost = Read-Host " Remote Computer Name [Required] (e.g. FRONTDESK)"
        if (-not $rHost) { Write-Host " [!] Cancelled." -ForegroundColor Red; return }

        # 2. Share Name (Optional - Default Provided)
        $defShare = "QuickBooks"
        $rShare = Read-Host " Remote Share Name [Default: $defShare]"
        if (-not $rShare) { $rShare = $defShare }

        # 3. Filename (Mandatory)
        $rFile = Read-Host " File Name to Pull [Required] (e.g. Setup.exe)"
        if (-not $rFile) { Write-Host " [!] Cancelled." -ForegroundColor Red; return }

        # 4. Remote User (Optional - Default Provided)
        $defUser = "transfer"
        $rUser = Read-Host " Remote User [Default: $defUser]"
        if (-not $rUser) { $rUser = $defUser }
        
        # 5. Remote Password (Mandatory)
        # We read this as plain text so we can pass it to the tool argument string
        $rPass = Read-Host " Remote Password [Required]" 
        if (-not $rPass) { Write-Host " [!] Password required." -ForegroundColor Red; return }

        # Launch Tool (Passes all captured variables to the script)
        Invoke-AerosTool "Transfer-Helper.ps1" "-Mode Receiver -RemoteHost '$rHost' -RemoteShare '$rShare' -RemoteFile '$rFile' -RemoteUser '$rUser' -RemotePass '$rPass'"
    }

    # --- STATUS MODE ---
    elseif ($sel -eq '3') {
        Invoke-AerosTool "Transfer-Helper.ps1" "-Mode Status"
    }
}

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           AEROS MASTER TOOLKIT (Hybrid v3.1.1)        ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS & AUDIT]" -ForegroundColor Yellow
        Write-Host "  1.  System Health (Forensic4)      10. Monitor Inventory (Serials)"
        Write-Host "  2.  RAM Analysis                   11. OS Install Date Check"
        Write-Host "  3.  Outlook/Office Audit           12. Verify BelMonitor/GWN Post"
        Write-Host "  4.  Battery & UPS Check            13. ** MASTER FORENSIC REPORT **"
        Write-Host "  5.  Tail RMM Logs (Live)           16. Transfer-Wizard"
        Write-Host "  6.  Master Storage & User Audit    "
        Write-Host "  7.  Disk/Storage Inventory         " -ForegroundColor Green
        Write-Host "  9.  Network SpeedTest (Ookla)"  -ForegroundColor Green
        
        Write-Host "`n [MAINTENANCE & INSTALL]" -ForegroundColor Yellow
        Write-Host "  20. Create Scanner User (SMB)      27. Power Policy Enforcer"
        Write-Host "  21. Fix AccountEdge Lock           28. Install UPS Logger"
        Write-Host "  22. Dell Update (DCU)              29. Auto-Repair Windows"
        Write-Host "  23. Install Apps (Basic/Power)     30. Clean up C:\ Drive"
        Write-Host "  24. Install ScreenConnect          31. Remove Dell Command Update"
        Write-Host "  25. Install PowerShell 7           32. Clean Office MRU"
        Write-Host "  26. Kick RMM/EDR Agent             33. Virtual Display Manager" -ForegroundColor Green

        # Using a safer string here to avoid & parsing issues
        Write-Host "`n [SECURITY AND LOGS]" -ForegroundColor Yellow
        Write-Host "  40. Enforce BitLocker (Escrow)     42. Password Generator"
        Write-Host "  41. Password Expiry Policies       43. Incident Time Machine"
        
        Write-Host "`n Q. Quit" -ForegroundColor DarkCyan
        
        $sel = Read-Host "`n Command"
        
        switch ($sel) {
             # --- DIAGNOSTICS & AUDIT ---
             '1'  { Get-SystemHealth; pause }
             '2'  { Get-RAMReport; pause }
             '3'  { Get-OfficeAudit; pause }
             '4'  { Get-Battery; Invoke-UpsCheck; pause }
             '5'  { Get-RMMLog; pause }
    
             # NEW Unified Tool (Replaces old #6, #8, #13)
             '6'  { Get-StorageAudit; pause }

             # Shifted Items
             '7'  { Get-DiskInv; pause }        # Physical Disk Inventory (Moved from 11)
    
             # (User skipped #8 in menu)
    
             '9'  { Invoke-SpeedTest; pause }
             '10' { Get-MonitorInfo; pause }
             '11' { Get-OSAge; pause }          # Moved from 12
             '12' { Verify-BelMonitor; pause }  # Moved from 14
             '13' { Get-ForensicMaster; pause } # Moved from 15
             '16' { Invoke-TransferWizard; pause }  # <--- NEW ENTRY

             # --- MAINTENANCE & INSTALL (Unchanged) ---
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
             '33' { Invoke-VirtualDisp; pause }

              # --- SECURITY (Unchanged) ---
              '40' { Enable-BitLocker; pause }
               '41' { Set-Policies; pause }
              '42' { Gen-Password; pause }
               '43' { Get-Incidents; pause }

               'Q'  { return }
               'q'  { return }
            }
        }
    }

# Execution
if ($Host.Name -notmatch "ISE|Visual Studio Code") { Start-Aeros }