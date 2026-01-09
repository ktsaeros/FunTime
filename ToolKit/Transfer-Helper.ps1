<#
.SYNOPSIS
    Aeros Workgroup Transfer Wizard (v3.0)
    - SENDER: Auto-creates Users/Shares/Permissions.
    - RECEIVER: Explicit destination paths.
    - STATUS: Interactive log viewing.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Sender","Receiver","Status")]
    [string]$Mode,

    # Sender Params
    [string]$SourcePath,
    [string]$DestPath = "C:\Transfer",
    [string]$ShareName = "Transfer",
    [string]$TransferUser = "transfer",

    # Receiver Params
    [string]$RemoteHost,
    [string]$RemoteShare,
    [string]$RemoteFile,
    [string]$RemoteUser,
    [string]$RemotePass,
    [string]$LocalDestPath = "C:\Users\Public\Downloads"
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Show-Header {
    Write-Host "+-------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|         AEROS WORKGROUP FILE TRANSFER WIZARD          |" -ForegroundColor Cyan
    Write-Host "+-------------------------------------------------------+" -ForegroundColor Cyan
}

# --- SENDER MODE LOGIC ---
if ($Mode -eq "Sender") {
    Show-Header
    Write-Host " [MODE: SENDER]" -ForegroundColor Yellow

    if (-not (Test-Path $SourcePath)) { Write-Host " [!] Source file not found." -ForegroundColor Red; return }

    # 1. Prepare Folder
    if (-not (Test-Path $DestPath)) {
        New-Item -Path $DestPath -ItemType Directory -Force | Out-Null
        Write-Host " [+] Created folder: $DestPath" -ForegroundColor Green
    }

    # 2. Check/Create User
    $u = Get-LocalUser -Name $TransferUser -ErrorAction SilentlyContinue
    if (-not $u) {
        # Generate a complex password (required by default policies)
        $genPass = "Aeros" + (Get-Random -Minimum 1000 -Maximum 9999) + "!"
        $securePass = ConvertTo-SecureString $genPass -AsPlainText -Force
        
        New-LocalUser -Name $TransferUser -Password $securePass -Description "Aeros Transfer Account" | Out-Null
        Add-LocalGroupMember -Group "Users" -Member $TransferUser
        
        Write-Host " [+] Created User: $TransferUser" -ForegroundColor Green
        Write-Host "     PASSWORD: $genPass" -ForegroundColor Yellow  # <--- CRITICAL INFO
        Write-Host "     (Save this password for the Receiver!)" -ForegroundColor Gray
    } else {
        Write-Host " [=] User '$TransferUser' already exists." -ForegroundColor Gray
    }

    # 3. Check/Create Share
    $s = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
    if (-not $s) {
        New-SmbShare -Name $ShareName -Path $DestPath -FullAccess "Everyone" | Out-Null
        Write-Host " [+] Created Share: \\$env:COMPUTERNAME\$ShareName" -ForegroundColor Green
    } else {
        Write-Host " [=] Share '$ShareName' already exists." -ForegroundColor Gray
    }

    # 4. Move File & Fix Perms
    $fileName = Split-Path $SourcePath -Leaf
    $finalPath = Join-Path $DestPath $fileName
    
    Write-Host " Moving File..." -ForegroundColor Cyan
    Move-Item -Path $SourcePath -Destination $DestPath -Force

    Write-Host " Fixing NTFS Permissions..." -ForegroundColor Cyan
    $expr = "icacls `"$DestPath`" /grant Everyone:F /T"
    Invoke-Expression $expr | Out-Null

    Write-Host "`n [SUCCESS] READY FOR TRANSFER" -ForegroundColor Green
    Write-Host " Source: \\$env:COMPUTERNAME\$ShareName\$fileName"
}

# --- RECEIVER MODE LOGIC ---
if ($Mode -eq "Receiver") {
    Show-Header
    Write-Host " [MODE: RECEIVER]" -ForegroundColor Yellow
    
    # Validation
    if (-not $RemoteHost -or -not $RemoteFile) { Write-Host " [!] Missing RemoteHost or Filename." -ForegroundColor Red; return }
    
    # Credential Handling
    try {
        if ($RemotePass) {
            $secPass = ConvertTo-SecureString $RemotePass -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ("$RemoteHost\$RemoteUser", $secPass)
        } else {
            $cred = Get-Credential "$RemoteHost\$RemoteUser"
        }
    } catch {
        Write-Host " [!] Credential Error." -ForegroundColor Red; return
    }

    # Ensure Local Dest Exists
    if (-not (Test-Path $LocalDestPath)) { New-Item -Path $LocalDestPath -ItemType Directory -Force | Out-Null }

    Write-Host " Starting Background Job..." -ForegroundColor Cyan
    Write-Host " Destination: $LocalDestPath" -ForegroundColor Gray

    $jobName = "Transfer_$($RemoteFile.Substring(0, [math]::Min(10, $RemoteFile.Length)))"

    $job = Start-Job -Name $jobName -ScriptBlock {
        param($c, $rHost, $rShare, $fName, $lDest)
        
        # Map Drive
        if (Test-Path "Q:") { Remove-PSDrive "Q" -Force -ErrorAction SilentlyContinue }
        try {
            New-PSDrive -Name "Q" -PSProvider FileSystem -Root "\\$rHost\$rShare" -Credential $c -Persist -ErrorAction Stop | Out-Null
        } catch {
            return "ERROR: Could not map drive. Check Password or Share Name.`n$($_.Exception.Message)"
        }

        # Copy
        $log = robocopy "Q:\" $lDest $fName /Z /NP /R:5 /W:5
        
        # Cleanup
        Remove-PSDrive "Q"
        return $log
    } -ArgumentList $cred, $RemoteHost, $RemoteShare, $RemoteFile, $LocalDestPath

    Write-Host " [SUCCESS] Job Started: $($job.Name)" -ForegroundColor Green
}

# --- STATUS MODE LOGIC ---
if ($Mode -eq "Status") {
    Show-Header
    $jobs = Get-Job | Where-Object { $_.Name -like "Transfer_*" }
    
    if ($jobs) {
        $jobs | Select-Object Id, Name, State, Location | Format-Table -AutoSize
        
        # Interactive Log Viewer
        Write-Host " Enter Job ID to view logs (or Press Enter to exit):" -NoNewline
        $id = Read-Host
        if ($id) {
            $j = Get-Job -Id $id -ErrorAction SilentlyContinue
            if ($j) {
                Write-Host "`n --- LOG OUTPUT START ---" -ForegroundColor Yellow
                Receive-Job -Id $j.Id -Keep
                Write-Host " --- LOG OUTPUT END --- `n" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host " No active transfer jobs." -ForegroundColor Yellow
    }
}