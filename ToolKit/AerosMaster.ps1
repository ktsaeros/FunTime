<#
.SYNOPSIS
    AEROS MASTER TOOLKIT (Hybrid v3.2 - Flight Recorder Edition)
    - Added: Flight Recorder Installer, Investigator (v2.9), and Remover.
    - Fixed: String termination errors and ampersand parsing issues.
#>

# --- Loaders ---
function Invoke-AerosScript {
    param([string]$ScriptName)
    # Generate a unique string based on the current second to bypass all web caches
    $CacheBuster = Get-Date -Format "ssmmHH"
    $RepoRoot = "https://raw.githubusercontent.com/ktsaeros/FunTime/main/ToolKit"
    $TargetUrl = "$RepoRoot/$ScriptName?v=$CacheBuster" # Adds ?v=123456 to the URL
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "   [Launcher] Fetching (Live): $ScriptName" -ForegroundColor Cyan
    
    try {
        $Code = Invoke-RestMethod -Uri $TargetUrl -UseBasicParsing -Headers @{ "Cache-Control" = "no-cache" }
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
function Get-DomainAudit {
    $Domain = Read-Host "`n Enter Domain (e.g. varietywire.com)"
    if ([string]::IsNullOrWhiteSpace($Domain)) { return }

    # Server API Details
    $ApiUrl = "https://crisps.fit/tools/run_audit.php"
    $ApiKey = "AerosFlight36"
    
    Write-Host "`n [Server] Auditing $Domain via crisps.fit..." -ForegroundColor Cyan

    try {
        # Fetch text result from server
        $Result = Invoke-RestMethod -Uri "$ApiUrl?key=$ApiKey&domain=$Domain" -UseBasicParsing
        
        # Display
        Write-Host $Result -ForegroundColor White
    }
    catch {
        Write-Error "Connection Failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
             $Reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
             Write-Host "Server Message: $($Reader.ReadToEnd())" -ForegroundColor Red
        }
    }
}


function Get-SystemHealth   { Invoke-AerosTool "forensic4.ps1" "" }
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
function Clean-CDrive       { Invoke-AerosScript "Triage-Cleanup.ps1" }

function Get-PrinterAudit {
    param([bool]$PurgeMode = $false)
    # Use a unique variable name and leave it null if not purging
    $PurgeArg = if ($PurgeMode) { "-Purge" } else { $null }
    
    # Only pass the argument if it exists
    if ($PurgeArg) {
        Invoke-AerosTool "Get-PrinterAudit.ps1" $PurgeArg
    } else {
        Invoke-AerosTool "Get-PrinterAudit.ps1" ""
    }
}

# Unified Storage & User Audit
function Get-StorageAudit   { Invoke-AerosScript "storage-audit.ps1" }

# FLIGHT RECORDER SUITE (NEW)
function Install-Recorder   { Invoke-AerosTool "Install-FlightRecorder.ps1" "" } # Must be 'Tool' to persist file copy
function Get-FlightCheck    { Invoke-AerosScript "Get-FlightAnalysis.ps1" }      # v2.9 Investigator
function Remove-Recorder    { Invoke-AerosScript "Remove-FlightRecorder.ps1" }

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
function Remove-DellCmd     { Invoke-AerosTool "Remove-DellCommand.ps1" "" }
function Clean-OfficeMRU    { Invoke-AerosTool "Clean-OfficeMRU.ps1" "" }
function Invoke-VirtualDisp { Invoke-AerosScript "usbmmidd.ps1" }

# Security
function Enable-BitLocker   { Invoke-AerosScript "btlon.ps1" }
function Set-Policies       { Invoke-AerosScript "Set-SecurityPolicies.ps1" }
function Gen-Password       { Invoke-AerosScript "Generate-Passwords.ps1" }
function Get-Incidents      { Invoke-AerosTool "get-incidents.ps1" "" }

function Invoke-TransferWizard {
    Clear-Host
    Write-Host " [AEROS ZIP-AND-SHIP WIZARD v4]" -ForegroundColor Cyan
    Write-Host " 1. Sender (Zip, Create User/Share)"
    Write-Host " 2. Receiver (Pull Zip from Remote)"
    Write-Host " 3. Check Job Status"
    Write-Host " 4. Cleanup Sender (Delete User/Share/Zip)" -ForegroundColor Red
    Write-Host " Q. Back"
    
    Write-Host "`n Select Option:" -NoNewline
    $sel = Read-Host
    
    # --- SENDER ---
    if ($sel -eq '1') {
        Write-Host "`n --- SENDER SETUP ---" -ForegroundColor Yellow
        Write-Host " Source File or Folder to Compress [Required]:" -ForegroundColor Cyan
        $src = Read-Host
        if (-not $src) { return }
        
        Invoke-AerosTool "Transfer-Helper.ps1" "-Mode Sender -SourcePath '$src'"
    }

    # --- RECEIVER ---
    elseif ($sel -eq '2') {
        Write-Host "`n --- RECEIVER SETUP ---" -ForegroundColor Yellow
        Write-Host " Remote Computer Name [Required]:" -ForegroundColor Cyan
        $rHost = Read-Host
        if (-not $rHost) { return }

        Write-Host " Remote Password [Required]:" -ForegroundColor Cyan
        $rPass = Read-Host 
        if (-not $rPass) { return }

        # Note: We don't ask for Share/User/File because we know them (Transfer/transfer/Transfer.zip)
        Invoke-AerosTool "Transfer-Helper.ps1" "-Mode Receiver -RemoteHost '$rHost' -RemotePass '$rPass'"
    }

    # --- STATUS ---
    elseif ($sel -eq '3') {
        Invoke-AerosTool "Transfer-Helper.ps1" "-Mode Status"
    }

    # --- CLEANUP ---
    elseif ($sel -eq '4') {
        Write-Host "`n [!] WARNING: This will delete the 'transfer' user and 'C:\Aeros\Transfer' folder." -ForegroundColor Red
        Write-Host " Are you sure? (Y/N):" -NoNewline
        $confirm = Read-Host
        if ($confirm -eq 'Y' -or $confirm -eq 'y') {
            Invoke-AerosTool "Transfer-Helper.ps1" "-Mode Cleanup"
        }
    }
}

function Start-Aeros {
    while ($true) {
        Clear-Host
        Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║           AEROS MASTER TOOLKIT (Hybrid v3.2)          ║" -ForegroundColor Cyan
        Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        
        Write-Host " [DIAGNOSTICS & AUDIT]" -ForegroundColor Yellow
        Write-Host "  1.  System Health (Forensic4)      10. Monitor Inventory (Serials)"
        Write-Host "  2.  RAM Analysis                   11. OS Install Date Check"
        Write-Host "  3.  Outlook/Office Audit           12. Verify BelMonitor/GWN Post"
        Write-Host "  4.  Battery & UPS Check            13. MASTER FORENSIC REPORT"
        Write-Host "  5.  Tail RMM Logs (Live)           14. FLIGHT RECORDER ANALYSIS"
        Write-Host "  6.  Master Storage & User Audit    16. Transfer-Wizard"
        Write-Host "  7.  Disk/Storage Inventory         17. Printer Audit                       " -ForegroundColor Green
        Write-Host "  9.  Network SpeedTest (Ookla)"                             -ForegroundColor Green
        
        Write-Host "`n [MAINTENANCE & INSTALL]" -ForegroundColor Yellow
        Write-Host "  20. Create Scanner User (SMB)      27. Power Policy Enforcer"
        Write-Host "  21. Fix AccountEdge Lock           28. Install UPS Logger"
        Write-Host "  22. Dell Update (DCU)              29. Auto-Repair Windows"
        Write-Host "  23. Install Apps (Basic/Power)     30. Clean up C:\ Drive"
        Write-Host "  24. Install ScreenConnect          31. Remove Dell Command Update"
        Write-Host "  25. Install PowerShell 7           32. Clean Office MRU"
        Write-Host "  26. Kick RMM/EDR Agent             33. Virtual Display Manager" 
        Write-Host "                                     34. Install Flight Recorder (Deploy)" -ForegroundColor Magenta
        Write-Host "                                     35. Remove Flight Recorder" -ForegroundColor DarkGray
        Write-Host "                                     36. Domain Infrastructure Audit (Python)" -ForegroundColor Cyan 

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
             '7'  { Get-DiskInv; pause }        
    
             '9'  { Invoke-SpeedTest; pause }
             '10' { Get-MonitorInfo; pause }
             '11' { Get-OSAge; pause }          
             '12' { Verify-BelMonitor; pause }  
             '13' { Get-ForensicMaster; pause } 
             '14' { Get-FlightCheck; pause }    # <--- NEW INVESTIGATOR
             '16' { Invoke-TransferWizard; pause } 
             '17'  { Get-PrinterAudit; pause }
             '177' { Get-PrinterAudit -PurgeMode $true; pause } # Hidden "Nuke" option

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
             '34' { Install-Recorder; pause }   # <--- NEW INSTALLER
             '35' { Remove-Recorder; pause }    # <--- NEW REMOVER
             '36' { Get-DomainAudit; pause }    # <--- NEW DOMAIN AUDIT

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